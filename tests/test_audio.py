#!/usr/bin/python3
"""The decisions of waypipe-audio, which need no GStreamer. Run: tests/test_audio.py"""
import importlib.machinery
import importlib.util
import os
import random
import tempfile
import unittest

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "waypipe-audio")
_loader = importlib.machinery.SourceFileLoader("waypipe_audio", _path)
_spec = importlib.util.spec_from_loader("waypipe_audio", _loader)
audio = importlib.util.module_from_spec(_spec)
_loader.exec_module(audio)


class Controller(unittest.TestCase):
    def converge(self, picture, extra, floor, t=100.0, offset=0.0, ticks=40, seed=1, noise=2.0):
        """Run the loop against a simulated pipeline; returns T and the last error."""
        rng = random.Random(seed)
        error = 0.0
        for _ in range(ticks):
            sound = audio.sound_delay_ms(t, extra, 0.0, offset)
            error = picture + rng.uniform(-noise, noise) - sound
            t = audio.next_t_ms(t, error, floor)
        return t, picture - audio.sound_delay_ms(t, extra, 0.0, offset)

    def test_levels_the_two_delays_from_either_side(self):
        for start in (40.0, 100.0, 400.0):
            for picture in (90.0, 200.0, 350.0):
                _t, error = self.converge(picture, 30.0, 10.0, t=start)
                self.assertLessEqual(abs(error), audio.DEADBAND_MS + 2.0, (start, picture))

    def test_follows_a_change_of_the_picture(self):
        t, _ = self.converge(100.0, 20.0, 10.0)
        _t, error = self.converge(180.0, 20.0, 10.0, t=t, ticks=12)
        self.assertLessEqual(abs(error), audio.DEADBAND_MS + 2.0)

    def test_inside_the_deadband_t_stays(self):
        self.assertEqual(audio.next_t_ms(100.0, audio.DEADBAND_MS, 0.0), 100.0)
        self.assertEqual(audio.next_t_ms(100.0, -audio.DEADBAND_MS, 0.0), 100.0)
        self.assertNotEqual(audio.next_t_ms(100.0, audio.DEADBAND_MS + 1, 0.0), 100.0)

    def test_never_leaves_its_bounds(self):
        self.assertEqual(audio.next_t_ms(100.0, -1000.0, 80.0), 80.0)
        self.assertEqual(audio.next_t_ms(490.0, 1000.0, 80.0), audio.T_CEILING_MS)

    def test_a_raised_floor_moves_t_up_even_with_no_error(self):
        self.assertEqual(audio.next_t_ms(50.0, 0.0, 70.0), 70.0)

    def test_at_the_floor_the_sound_stays_later_and_the_error_remains(self):
        t, error = self.converge(50.0, 30.0, 60.0)
        self.assertEqual(t, 60.0)
        self.assertEqual(error, -40.0)

    def test_the_clock_offset_is_in_the_sound_delay(self):
        # Each clock difference must end at the same real delay, the picture's.
        for offset in (-50.0, 0.0, 50.0):
            _t, error = self.converge(120.0, 20.0, 0.0, t=200.0, offset=offset)
            self.assertLessEqual(abs(error), audio.DEADBAND_MS + 2.0, offset)

    def test_holds_over_seeds(self):
        for seed in range(20):
            _t, error = self.converge(150.0, 25.0, 10.0, seed=seed)
            self.assertLessEqual(abs(error), audio.DEADBAND_MS + 2.0, seed)


class Measures(unittest.TestCase):
    def test_floor_grows_with_jitter_and_with_late_packets(self):
        steady = [64.0] * 20
        jittery = [64.0] * 15 + [100.0] * 5
        self.assertEqual(audio.jitter_floor_ms(steady, 0.0), 32.0)
        self.assertGreater(audio.jitter_floor_ms(jittery, 0.0), 32.0)
        self.assertEqual(audio.jitter_floor_ms(steady, 7.0), 39.0)

    def test_late_packets_raise_the_floor_and_it_comes_back_down(self):
        boost = audio.next_boost_ms(0.0, 2, 10.0)
        self.assertEqual(boost, 11.0)
        self.assertEqual(audio.next_boost_ms(boost, 1, 10.0), 22.0)
        for _ in range(200):
            boost = audio.next_boost_ms(boost, 0, 10.0)
        self.assertLess(boost, 1.0)

    def test_no_measurement_uses_the_fallback(self):
        self.assertEqual(audio.jitter_floor_ms([], 0.0), audio.NO_MEASURE_T_MS)

    def test_picture_delay_takes_off_the_way_back_and_stays_above_zero(self):
        self.assertEqual(audio.picture_delay_ms(100.0, 60.0), 70.0)
        self.assertEqual(audio.picture_delay_ms(10.0, 60.0), 0.0)

    def test_clock_offset_of_a_symmetric_exchange(self):
        # Sent at 10.0 here, received at 10.1; the other clock read 15.05 halfway: 5 s ahead.
        self.assertAlmostEqual(audio.clock_offset_ms(10.0, 15.05, 10.1), 5000.0)

    def test_sound_delay_sign_of_the_offset(self):
        # A receiver clock 10 ms ahead plays a sample's time 10 ms sooner in real time.
        self.assertEqual(audio.sound_delay_ms(100.0, 20.0, 5.0, 10.0), 115.0)


class Reports(unittest.TestCase):
    def test_round_trip_of_a_report(self):
        self.assertEqual(audio.parse_report(b"R rtt=64.0 floor=32.5"), {"rtt": 64.0, "floor": 32.5})

    def test_anything_else_is_ignored(self):
        for data in (b"p12", b"R", b"R x", b"R a=b", b""):
            self.assertIn(audio.parse_report(data), (None, {}), data)

    def test_frame_time_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t")
            self.assertIsNone(audio.read_frame_time_ms(path))
            with open(path, "w") as f:
                f.write("87\n")
            self.assertEqual(audio.read_frame_time_ms(path), 87.0)
            with open(path, "w") as f:
                f.write("junk")
            self.assertIsNone(audio.read_frame_time_ms(path))


if __name__ == "__main__":
    unittest.main()
