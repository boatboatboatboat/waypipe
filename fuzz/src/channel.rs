/* SPDX-License-Identifier: GPL-3.0-or-later */
#![no_main]
/*! Fuzzing hook which runs the main loop; on one side against well formed Wayland
 * protocol data, on the other side against arbitrary channel messages.
 *
 * Set environment variable FUZZ_RENDER_NODE to enable DMABUF support.
 *
 * There are no memory limits. */

use libfuzzer_sys::fuzz_target;

use log::{debug, LevelFilter, Log, Record};
use mainloop::util::{
    Compression, VideoFormat, VideoSetting, MIN_PROTOCOL_VERSION, WAYPIPE_PROTOCOL_VERSION,
};
use mainloop::*;
use nix::errno::Errno;
use nix::fcntl;
use nix::sys::memfd;
use nix::sys::resource;
use nix::sys::signal;
use nix::sys::socket;
use nix::sys::stat;
use nix::sys::uio;
use nix::{poll, unistd};
use std::collections::VecDeque;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::thread;

const DUMMY_OBJECT_ID: u32 = 0xfffffff;
const WL_DISPLAY_ID: u32 = 1;
const WL_DISPLAY_ERROR_OPCODE: u8 = 0;

struct ThreadLogger;

impl Log for ThreadLogger {
    fn enabled(&self, _meta: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &Record<'_>) {
        use std::io::Write;

        let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let t = if let Ok(t) = time {
            (t.as_nanos() % 100000000000u128) / 1000u128
        } else {
            0
        };

        let thread = std::thread::current();

        let lvl_str: &str = match record.level() {
            log::Level::Error => "ERR",
            log::Level::Warn => "Wrn",
            log::Level::Debug => "dbg",
            log::Level::Info => "inf",
            log::Level::Trace => "trc",
        };

        const MAX_LOG_LEN: usize = 512;
        let mut buf = [0u8; MAX_LOG_LEN];
        let mut cursor = std::io::Cursor::new(&mut buf[..MAX_LOG_LEN - 5]);
        let _ = writeln!(
            &mut cursor,
            "[{:02}.{:06} {} {}({}) {}:{}] {}",
            t / 1000000u128,
            t % 1000000u128,
            lvl_str,
            thread.name().unwrap_or("unknown"),
            unistd::gettid(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args(),
        );
        let mut str_end = cursor.position() as usize;

        if str_end >= MAX_LOG_LEN - 10 {
            /* Deal with possible partial UTF-8 char */
            str_end = match std::str::from_utf8(&buf[..str_end]) {
                Ok(x) => x.len(),
                Err(y) => y.valid_up_to(),
            };

            /* Assume message was truncated */
            assert!(str_end <= MAX_LOG_LEN - 4, "{} {}", str_end, MAX_LOG_LEN);
            buf[str_end..str_end + 3].fill(b'.');
            buf[str_end + 3] = b'\n';
            str_end += 4;
        }
        let handle = &mut std::io::stderr().lock();
        handle.write_all(&buf[..str_end]).expect("stderr is OK");
        handle.flush().expect("stderr is OK");
    }
    fn flush(&self) {
        /* not needed */
    }
}

fn wl_end_message() -> [u8; 8] {
    let a = DUMMY_OBJECT_ID.to_le_bytes();
    let b = (8u32 << 16).to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

fn wp_end_message() -> [u8; 12] {
    const PROTOCOL: u32 = 0;
    let a = ((12 << 5) | PROTOCOL).to_le_bytes();
    let b = DUMMY_OBJECT_ID.to_le_bytes();
    let c = (8u32 << 16).to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3],
    ]
}

fn parse_wl_header(msg: &[u8]) -> (u32, usize, u8) {
    let obj_id = u32::from_le_bytes(msg[0..4].try_into().unwrap());
    let x = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    let length = (x >> 16) as usize;
    let opcode = (x & 0x00ff) as u8;
    (obj_id, length, opcode)
}

fn parse_wp_header(msg: &[u8]) -> (u8, u32) {
    let header = u32::from_le_bytes(msg[0..4].try_into().unwrap());
    let code = (header & ((1 << 5) - 1)) as u8;
    let len = header >> 5;
    (code, len)
}

#[derive(Default)]
struct SideState {
    wayland_bytes: Vec<u8>,
    wayland_fds: Vec<OwnedFd>,

    pipes: VecDeque<OwnedFd>,
    shm: VecDeque<OwnedFd>,
    dmabufs: VecDeque<OwnedFd>,
    // TODO: add timeline semaphores
}

/** Write a batch of messages with associated FDs to `src_fd`, followed by
 * a message that should pass either through cleanly, or end with an error
 * directed to the program.
 *
 * This returns the FDs read from `wayl_fd`, on success; if both
 * endpoints close this returns Err(());
 */
fn interact(
    wayl_fd: &OwnedFd,
    chan_fd: &OwnedFd,
    write_to_wayl: bool,
    data: &[u8],
    mut fds: &[&OwnedFd],
    timeout: f64,
) -> Result<Vec<OwnedFd>, ()> {
    let wl_end = wl_end_message();
    let wp_end = wp_end_message();
    let end_msg_send = if write_to_wayl {
        &wl_end[..]
    } else {
        &wp_end[..]
    };

    let mut nbytes_sent: usize = 0;
    let mut nfds_sent: usize = 0;
    let net_len = data.len() + end_msg_send.len();

    let raw_fds: Vec<i32> = fds.iter().map(|x| x.as_raw_fd()).collect();

    /* Note: libwayland sends up to 28 fds per byte, Waypipe can receive a bit more.
     * Drop any excess file descriptors.
     */
    const MAX_FDS_PER_BYTE: usize = 32;
    fds = &fds[..fds.len().min(data.len().saturating_mul(MAX_FDS_PER_BYTE))];

    enum ReadExtra {
        Wayland(Vec<OwnedFd>),
        Channel,
    }

    struct ReadState {
        data: Vec<u8>,
        rmsgs: Vec<Vec<u8>>,
        extra: ReadExtra,
        eof: bool,
    }

    let mut recv_wayl = ReadState {
        data: Vec::new(),
        extra: ReadExtra::Wayland(Vec::new()),
        rmsgs: Vec::new(),
        eof: false,
    };
    let mut recv_chan = ReadState {
        data: Vec::new(),
        extra: ReadExtra::Channel,
        rmsgs: Vec::new(),
        eof: false,
    };

    loop {
        let mut pfds = Vec::new();
        let mut recvs: Vec<&mut ReadState> = Vec::new();
        let writing = nbytes_sent < net_len;
        if !recv_wayl.eof {
            pfds.push(poll::PollFd::new(
                wayl_fd.as_fd(),
                if writing && write_to_wayl {
                    poll::PollFlags::POLLIN | poll::PollFlags::POLLOUT
                } else {
                    poll::PollFlags::POLLIN
                },
            ));
            recvs.push(&mut recv_wayl);
        }
        if !recv_chan.eof {
            pfds.push(poll::PollFd::new(
                chan_fd.as_fd(),
                if writing && !write_to_wayl {
                    poll::PollFlags::POLLIN | poll::PollFlags::POLLOUT
                } else {
                    poll::PollFlags::POLLIN
                },
            ));
            recvs.push(&mut recv_chan);
        }

        let timeout =
            nix::sys::time::TimeSpec::new(timeout.floor() as _, (timeout.fract() * 1e9) as _);

        let res = nix::poll::ppoll(&mut pfds, Some(timeout), None);
        if let Err(e) = res {
            assert!(e == Errno::EINTR || e == Errno::EAGAIN);
            continue;
        }

        if pfds.len() == 0 {
            debug!("{}-sec timeout while writing", timeout);
            return Err(());
        }

        for (pfd, recv) in pfds.into_iter().zip(recvs) {
            let evt = pfd.revents().unwrap();

            if evt.contains(poll::PollFlags::POLLIN) {
                assert!(!recv.eof);
                let mut tmp = vec![0u8; 16384];
                let mut iovs = [IoSliceMut::new(&mut tmp)];
                let mut cmsg_fds = nix::cmsg_space!([RawFd; 32]);

                let r = socket::recvmsg::<socket::UnixAddr>(
                    pfd.as_fd().as_raw_fd(),
                    &mut iovs,
                    Some(&mut cmsg_fds),
                    socket::MsgFlags::empty(),
                );
                match r {
                    Ok(resp) => {
                        for msg in resp.cmsgs().unwrap() {
                            match msg {
                                socket::ControlMessageOwned::ScmRights(tfds) => {
                                    for f in &tfds {
                                        assert!(*f != -1);
                                        let ReadExtra::Wayland(fds) = &mut recv.extra else {
                                            unreachable!();
                                        };

                                        fds.push(unsafe {
                                            // SAFETY: fd was just created, checked valid,
                                            // and is recorded nowhere else
                                            OwnedFd::from_raw_fd(*f)
                                        });
                                    }
                                }
                                _ => {
                                    panic!("Unexpected control message");
                                }
                            }
                        }

                        let nbytes = resp.bytes;
                        recv.data.extend_from_slice(&tmp[..nbytes]);

                        recv.eof = nbytes == 0;
                    }
                    Err(nix::errno::Errno::ECONNRESET) => {
                        recv.eof = true;
                    }
                    Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => (),
                    Err(x) => {
                        panic!("Error reading from socket: {:?}", x)
                    }
                }

                /* Extract any complete messages from stream */
                match recv.extra {
                    ReadExtra::Channel => {
                        let mut tail: &[u8] = &recv.data;
                        while tail.len() >= 4 {
                            let (_code, length) = parse_wp_header(tail);
                            /* Waypipe should only ever write valid messages */
                            assert!(length >= 4);
                            let length = length.next_multiple_of(4);
                            if tail.len() < length as usize {
                                break;
                            };
                            let (msg, nxt) = tail.split_at(length as usize);
                            recv.rmsgs.push(msg.into());
                            tail = nxt;
                        }
                        recv.data.drain(..(recv.data.len() - tail.len()));
                    }
                    ReadExtra::Wayland(_) => {
                        let mut tail: &[u8] = &recv.data;
                        while tail.len() >= 8 {
                            let (_obj_id, length, _opcode) = parse_wl_header(tail);
                            /* Waypipe should only ever write valid messages */
                            assert!(length >= 8 && length % 4 == 0);
                            if tail.len() < length {
                                break;
                            }
                            let (msg, nxt) = tail.split_at(length);
                            recv.rmsgs.push(msg.into());
                            tail = nxt;
                        }
                        recv.data.drain(..(recv.data.len() - tail.len()));
                    }
                }
            } else if evt.intersects(poll::PollFlags::POLLHUP | poll::PollFlags::POLLERR) {
                recv.eof = true;
            }

            if evt.contains(poll::PollFlags::POLLOUT) {
                /* Only the writing side checks for POLLOUT, so write messages here */
                let iovs_long = [
                    IoSlice::new(&data[std::cmp::min(nbytes_sent, data.len())..]),
                    IoSlice::new(
                        &end_msg_send[(std::cmp::max(nbytes_sent, data.len()) - data.len())..],
                    ),
                ];
                let iovs_short = [IoSlice::new(if nbytes_sent >= data.len() {
                    &end_msg_send[nbytes_sent - data.len()..(nbytes_sent - data.len() + 1)]
                } else {
                    &data[nbytes_sent..(nbytes_sent + 1)]
                })];
                let sfds =
                    &raw_fds[nfds_sent..std::cmp::min(fds.len(), nfds_sent + MAX_FDS_PER_BYTE)];
                let short_transfer = !sfds.is_empty() || fds.len() > nfds_sent + MAX_FDS_PER_BYTE;
                let iovs: &[IoSlice] = if short_transfer {
                    &iovs_short
                } else {
                    &iovs_long
                };
                let cmsgs = [socket::ControlMessage::ScmRights(sfds)];

                let r = nix::sys::socket::sendmsg::<()>(
                    pfd.as_fd().as_raw_fd(),
                    iovs,
                    if sfds.is_empty() { &[] } else { &cmsgs },
                    nix::sys::socket::MsgFlags::empty(),
                    None,
                );
                match r {
                    Ok(s) => {
                        nbytes_sent += s;
                        nfds_sent += sfds.len();
                    }
                    Err(Errno::EINTR) | Err(Errno::EAGAIN) => {
                        println!("eintr");
                    }
                    Err(Errno::EPIPE) | Err(Errno::ECONNRESET) => {
                        recv.eof = true;
                    }
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                }
            }
        }

        if recv_chan.eof && recv_wayl.eof {
            return Err(());
        }

        let mut done = false;

        for msg in recv_chan.rmsgs.iter() {
            if parse_wp_header(msg).0 == 0 {
                let mut tail: &[u8] = &msg[4..];
                while tail.len() >= 8 {
                    let (_obj_id, length, _opcode) = parse_wl_header(tail);
                    /* Waypipe should only ever write valid messages */
                    assert!(length >= 8 && length % 4 == 0);
                    if tail.len() < length {
                        break;
                    }
                    let (wlmsg, nxt) = tail.split_at(length);
                    tail = nxt;

                    if wlmsg == wl_end_message() && write_to_wayl {
                        done = true;
                    }

                    let (obj_id, _length, opcode) = parse_wl_header(wlmsg);
                    if obj_id == WL_DISPLAY_ID && opcode == WL_DISPLAY_ERROR_OPCODE {
                        done = true;
                    }
                }
            }
        }

        for msg in &recv_wayl.rmsgs {
            let (obj_id, _length, opcode) = parse_wl_header(msg);

            if msg == &wl_end_message() && !write_to_wayl {
                done = true;
            }

            if obj_id == WL_DISPLAY_ID && opcode == WL_DISPLAY_ERROR_OPCODE {
                done = true;
            }
        }

        if done {
            break;
        }
    }

    let ReadExtra::Wayland(fds) = recv_wayl.extra else {
        unreachable!();
    };

    Ok(fds)
}

fn is_pipe(fd: &OwnedFd) -> bool {
    let info = stat::fstat(fd).unwrap();
    (info.st_mode & stat::SFlag::S_IFMT.bits()) == stat::SFlag::S_IFIFO.bits()
}

fn is_shm(fd: &OwnedFd) -> bool {
    let info = stat::fstat(fd).unwrap();
    (info.st_mode & stat::SFlag::S_IFMT.bits()) == stat::SFlag::S_IFREG.bits()
}

fn make_shm(len: usize) -> OwnedFd {
    let local_fd = memfd::memfd_create(
        c"/waypipe",
        memfd::MFdFlags::MFD_CLOEXEC | memfd::MFdFlags::MFD_ALLOW_SEALING,
    )
    .unwrap();

    let data: Vec<u8> = (0..len).map(|x| if x % 2 != 0 { 255 } else { 0 }).collect();
    let b = unistd::write(&local_fd, &data).unwrap();
    assert!(b == data.len());

    local_fd
}

fn make_pipe() -> (OwnedFd, OwnedFd) {
    unistd::pipe2(fcntl::OFlag::O_NONBLOCK | fcntl::OFlag::O_CLOEXEC).unwrap()
}

fn get_shm_len(fd: &OwnedFd) -> u64 {
    let info = stat::fstat(fd).unwrap();
    info.st_size.try_into().unwrap()
}

/* Interpret `data` as a series of chunks, which look like Wayland protocol and
 * either are routed as Wayland protocol messages; as data for the channel; or
 * control messages. Each is followed by a dummy message used to
 * confirm the queue has been flushed. */

fn run_half(
    chan_fd: OwnedFd,
    wayl_fd: OwnedFd,
    mut data: &[u8],
    drm_node: Option<PathBuf>,
    timeout: f64,
) {
    let mut wayl_side = SideState::default();

    let mut channel_queue = Vec::new();

    let mut scratch = [0u8; 1 << 16];

    let mut vulkan = None;

    /* It doesn't really matter which side sends messages first */
    let mut last_wayl_side = true;
    loop {
        let Some((code, tail)) = data.split_first_chunk::<4>() else {
            return;
        };
        data = tail;
        let mut code = u32::from_le_bytes(*code);
        let is_wayl_side = (code & 0x1) != 0;
        code >>= 1;

        /* Each action only affects a single side, and when the side changes
         * all actions are flushed.
         *
         * The side transition behavior should also help synchronize (and make a
         * bit more reproducible) fd operations on both sides of the connection */
        if is_wayl_side != last_wayl_side {
            let (msgs, fd_refs) = if is_wayl_side {
                debug!(
                    "Sending {} bytes + {} fds of messages over wayland",
                    wayl_side.wayland_bytes.len(),
                    wayl_side.wayland_fds.len()
                );
                (
                    &wayl_side.wayland_bytes,
                    wayl_side.wayland_fds.iter().collect(),
                )
            } else {
                debug!(
                    "Sending {} bytes of messages over channel",
                    channel_queue.len()
                );
                (&channel_queue, Vec::new())
            };

            let Ok(wayl_fds) = interact(&wayl_fd, &chan_fd, is_wayl_side, msgs, &fd_refs, timeout)
            else {
                return;
            };

            if is_wayl_side {
                wayl_side.wayland_bytes.clear();
                wayl_side.wayland_fds.clear();
            } else {
                channel_queue.clear();
            }

            for fd in wayl_fds {
                if is_shm(&fd) {
                    wayl_side.shm.push_back(fd);
                } else if is_pipe(&fd) {
                    wayl_side.pipes.push_back(fd);
                } else {
                    // TODO: identify dmabuf or semaphore +
                    // extract whatever properties needed to modify it.
                }
            }

            last_wayl_side = is_wayl_side;
        }

        if !is_wayl_side {
            /* Queue following channel message */
            if data.len() < 4 {
                /* Not enough space for header */
                return;
            }
            let (code, len) = parse_wp_header(&data[..4]);
            if len == 0 {
                return;
            }
            let len = len.next_multiple_of(4);
            let Some((msg, tail)) = data.split_at_checked(len as usize) else {
                return;
            };
            data = tail;

            if code == 0 && len >= 12 && parse_wl_header(&msg[4..12]).0 == DUMMY_OBJECT_ID {
                /* Prevent confusion with end message */
                return;
            }

            debug!("Queuing {}-byte message for channel", msg.len());
            channel_queue.extend_from_slice(msg);
            continue;
        }

        match code {
            0 => {
                /* Queue following Wayland message */
                if data.len() < 8 {
                    /* Not enough space for header */
                    return;
                }
                let (obj, msg_len, _opcode) = parse_wl_header(&data[..8]);
                if obj == DUMMY_OBJECT_ID {
                    /* Prevent confusion with end message */
                    return;
                }
                if msg_len % 4 != 0 || msg_len < 8 {
                    return;
                }
                let Some((msg, tail)) = data.split_at_checked(msg_len) else {
                    return;
                };
                data = tail;
                debug!("Queuing {}-byte message for wayland", msg.len());
                wayl_side.wayland_bytes.extend_from_slice(msg);
            }
            1 => {
                /* Rotate target file descriptor */
                if !wayl_side.pipes.is_empty() {
                    let fd = wayl_side.pipes.pop_front().unwrap();
                    wayl_side.pipes.push_back(fd);
                }
                if !wayl_side.shm.is_empty() {
                    let fd = wayl_side.shm.pop_front().unwrap();
                    wayl_side.shm.push_back(fd);
                }
            }
            2 => {
                /* Create and submit SHM buffer of given size */
                let Some((len, tail)) = data.split_at_checked(8) else {
                    return;
                };
                data = tail;

                // TODO: lift this cap on high RAM systems; but larger files
                // risk making processing very slow
                let len = (u64::from_le_bytes(len.try_into().unwrap()) as usize).min(1 << 17);
                let fd = make_shm(len);
                wayl_side.wayland_fds.push(fd.try_clone().unwrap());
                wayl_side.shm.push_back(fd);
            }
            3 => {
                /* Create and submit read end of pipe */
                let (pipe_r, pipe_w) = make_pipe();
                wayl_side.wayland_fds.push(pipe_r);
                wayl_side.pipes.push_back(pipe_w);
            }
            4 => {
                /* Create and submit write end of pipe */
                let (pipe_r, pipe_w) = make_pipe();
                wayl_side.wayland_fds.push(pipe_w);
                wayl_side.pipes.push_back(pipe_r);
            }
            5 => {
                /* Close a pipe end */
                drop(wayl_side.pipes.pop_front());
            }
            6 => {
                /* Try to read N bytes from a pipe */
                let Some((len, tail)) = data.split_at_checked(4) else {
                    return;
                };
                data = tail;

                let len = (u32::from_le_bytes(len.try_into().unwrap()) as usize).min(scratch.len());
                if let Some(fd) = wayl_side.pipes.front() {
                    let _ = unistd::read(fd, &mut scratch[..len]);
                }
            }
            7 => {
                /* Try to write N bytes from a pipe */
                let Some((len, tail)) = data.split_at_checked(4) else {
                    return;
                };
                data = tail;

                let len = (u32::from_le_bytes(len.try_into().unwrap()) as usize).min(scratch.len());
                if let Some(fd) = wayl_side.pipes.front() {
                    let data = &mut scratch[..len];
                    for (i, d) in data.iter_mut().enumerate() {
                        *d = i as u8;
                    }
                    let _ = unistd::write(fd, data);
                }
            }
            8 => {
                /* Modify a range of bytes of shm buffer. Contents are not
                 * easily controllable because fuzzer commands should focus on behavior
                 * with likely bugs in _Waypipe's_ code, not in the compression/video
                 * libraries. */
                let Some((params, tail)) = data.split_at_checked(12) else {
                    return;
                };
                data = tail;

                let offset =
                    u64::from_le_bytes(params[..8].try_into().unwrap()).min(i64::MAX as u64);
                /* Longer stretches could amplify fuzzer cost / input length ratio;
                 * but of course running this operation multiple times lets the fuzzer still
                 * trigger large changes */
                let len = (u32::from_le_bytes(params[8..].try_into().unwrap()) as usize)
                    .min(scratch.len());

                if let Some(fd) = wayl_side.shm.front() {
                    let file_len = get_shm_len(fd);

                    if offset < file_len {
                        let tmp = &mut scratch[..(file_len - offset).min(len as u64) as usize];

                        assert_eq!(
                            uio::pread(fd, tmp, offset.try_into().unwrap()).unwrap(),
                            tmp.len()
                        );
                        for d in tmp.iter_mut() {
                            *d = d.wrapping_add(1);
                        }
                        assert_eq!(
                            uio::pwrite(fd, tmp, offset.try_into().unwrap()).unwrap(),
                            tmp.len()
                        );
                    }
                }
            }
            9 => {
                /* Fill a very short range of bytes of shm buffer, in case Waypipe reads the contents
                 * (dmabuf modifier tables, for example). */
                let Some((params, tail)) = data.split_at_checked(12) else {
                    return;
                };
                data = tail;

                let offset =
                    u64::from_le_bytes(params[..8].try_into().unwrap()).min(i64::MAX as u64);
                let len = (u32::from_le_bytes(params[8..].try_into().unwrap()) as usize).min(64);
                let Some((contents, tail)) = data.split_at_checked(len) else {
                    return;
                };
                data = tail;

                if let Some(fd) = wayl_side.shm.front() {
                    let file_len = get_shm_len(fd);

                    if offset < file_len {
                        let tmp = &mut scratch[..(file_len - offset).min(len as u64) as usize];
                        tmp.copy_from_slice(&contents[..tmp.len()]);
                        assert_eq!(
                            uio::pwrite(fd, tmp, offset.try_into().unwrap()).unwrap(),
                            tmp.len()
                        );
                    }
                }
            }
            10 => {
                /* Create DMABUF */
                let Some((info, tail)) = data.split_at_checked(20) else {
                    return;
                };
                data = tail;
                let width = u32::from_le_bytes(info[..4].try_into().unwrap());
                let mut height = u32::from_le_bytes(info[4..8].try_into().unwrap());
                // TODO: allow larger values on high RAM system
                if width == 0 {
                    return;
                }
                height = height.min((1 << 20) / width);
                if height == 0 {
                    return;
                }
                let drm_format = u32::from_le_bytes(info[8..12].try_into().unwrap());
                let modifier = u64::from_le_bytes(info[12..20].try_into().unwrap());

                if vulkan.is_none() {
                    let Some(path) = &drm_node else {
                        return;
                    };
                    let node_dev = platform::get_rdev_for_file(&path)
                        .expect("FUZZ_RENDER_NODE needs to be valid");

                    let no_video = VideoSetting {
                        format: None,
                        bits_per_frame: None,
                        enc_pref: None,
                        dec_pref: None,
                    };
                    let Ok(Some(inst)) =
                        dmabuf::setup_vulkan_instance(false, &no_video, false, false)
                    else {
                        return;
                    };
                    let Ok(Some(vulk)) =
                        dmabuf::setup_vulkan_device(&inst, Some(node_dev), &no_video, false)
                    else {
                        return;
                    };
                    vulkan = Some(vulk);
                }
                let vulk = vulkan.as_ref().unwrap();

                // TODO: for testing it may be more efficient to hold onto _buf
                // and use it to trigger modifications
                let Ok((_buf, add_planes)) = dmabuf::vulkan_create_dmabuf(
                    vulk,
                    width,
                    height,
                    drm_format,
                    &[modifier],
                    false,
                ) else {
                    return;
                };

                for plane in add_planes {
                    wayl_side.wayland_fds.push(plane.fd.try_clone().unwrap());
                    wayl_side.dmabufs.push_back(plane.fd);
                }
            }

            // Other cases: do nothing
            _ => continue,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((opt_control, data)) = data.split_first_chunk::<64>() else {
        return;
    };

    let debug = std::env::var_os("FUZZ_DEBUG").is_some();
    if debug {
        log::set_max_level(LevelFilter::Trace);
        let _ = log::set_logger(&ThreadLogger);
    }

    let timeout = std::env::var_os("FUZZ_TURN_TIMEOUT")
        .map(|s| {
            str::from_utf8(s.as_encoded_bytes())
                .unwrap()
                .parse::<f64>()
                .unwrap()
        })
        .unwrap_or(1.0f64);

    let has_gpu = std::env::var_os("FUZZ_RENDER_NODE").is_some();

    let version = if opt_control[0] & (1 << 0) != 0 {
        MIN_PROTOCOL_VERSION
    } else {
        WAYPIPE_PROTOCOL_VERSION
    };
    let on_display_side = opt_control[0] & (1 << 1) != 0;
    let skip_vulkan = opt_control[0] & (1 << 2) != 0;
    let no_timeline = opt_control[0] & (1 << 3) != 0;
    let compression = [Compression::None, Compression::Lz4(1), Compression::Zstd(1)]
        [((opt_control[0] >> 4) & (0x3)) as usize % 3];
    let video_format = [
        None,
        Some(VideoFormat::H264),
        Some(VideoFormat::VP9),
        Some(VideoFormat::AV1),
    ][((opt_control[0] >> 6) & (0x3)) as usize];

    let drm_node = std::env::var_os("FUZZ_RENDER_NODE").map(PathBuf::from);

    let opts = Options {
        debug,

        compression,
        video: VideoSetting {
            format: video_format,
            bits_per_frame: None,
            enc_pref: None,
            dec_pref: None,
        },
        threads: 2, /* two threads, to expose some complexity */
        title_prefix: "prefix-".to_string(),
        no_gpu: !has_gpu,
        drm_node: drm_node.clone(),
        test_skip_vulkan: skip_vulkan,
        test_no_timeline_export: no_timeline,
        test_no_binary_semaphore_import: false,
    };

    let sigaction = signal::SigAction::new(
        signal::SigHandler::SigIgn,
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        // SAFETY: nothing should unsafely rely on SIGPIPE
        signal::sigaction(signal::Signal::SIGPIPE, &sigaction).unwrap();
    }

    /* Some systems set the soft limit rather low (to 1024 fds) */
    let (_lim_soft, lim_hard) = resource::getrlimit(resource::Resource::RLIMIT_NOFILE).unwrap();
    resource::setrlimit(resource::Resource::RLIMIT_NOFILE, lim_hard, lim_hard).unwrap();

    let (test_chan, ctrl_chan) = socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        None,
        socket::SockFlag::SOCK_NONBLOCK | socket::SockFlag::SOCK_CLOEXEC,
    )
    .expect("socket creation succeeds");
    let (test_wayl, ctrl_wayl) = socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        None,
        socket::SockFlag::SOCK_NONBLOCK | socket::SockFlag::SOCK_CLOEXEC,
    )
    .expect("socket creation succeeds");

    let pollmask = signal::SigSet::empty();
    let stop_all = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let thread = thread::Builder::new()
            .name(
                (if on_display_side {
                    "waypipe-client"
                } else {
                    "waypipe-server"
                })
                .to_string(),
            )
            .spawn_scoped(scope, || {
                mainloop::main_interface_loop(
                    test_chan,
                    test_wayl,
                    &opts,
                    version,
                    on_display_side,
                    pollmask,
                    &stop_all,
                )
            })
            .expect("thread starting succeeds");

        run_half(ctrl_chan, ctrl_wayl, data, drm_node, timeout);

        /* Once both endpoints disconnect, the main loop thread should cleanly exit */
        thread.join().unwrap().unwrap();
    })
});
