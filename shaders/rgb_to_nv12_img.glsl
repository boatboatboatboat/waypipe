#version 450

layout(binding = 0) uniform sampler2D input_rgb;
layout(binding = 1) uniform restrict writeonly image2D output_y;
layout(binding = 2) uniform restrict writeonly image2D output_vu;

layout(push_constant) uniform constants {
  mat3x4 rgb_to_yrb;
  /* For a buffer with alpha, the frame row where its alpha plane starts (as
   * luma, under neutral chroma); else 0. A multiple of 16, so no 2x2 block
   * straddles it */
  int alpha_offset;
}
push;

/* Each individual task fills 2x2 pixels. */
/* note: AMD subgroupSize is 64, so 8x8 is needed to fully use it */
layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;
void main() {
  ivec2 brdim = imageSize(output_vu);
  ivec2 ydim = imageSize(output_y);
  ivec2 rgbdim = textureSize(input_rgb, 0);

  if (push.alpha_offset > 0 &&
      2 * int(gl_GlobalInvocationID.y) >= push.alpha_offset) {
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 2; j++) {
        ivec2 pos = ivec2(2 * gl_GlobalInvocationID.x + i,
                          2 * gl_GlobalInvocationID.y + j);
        vec2 sample_pos = vec2(pos.x, pos.y - push.alpha_offset) + 0.5;
        float a = texture(input_rgb, sample_pos).a;
        imageStore(output_y, pos, vec4(a, 1., 1., 1.));
      }
    }
    imageStore(output_vu, ivec2(gl_GlobalInvocationID.xy),
               vec4(128. / 255., 128. / 255., 1., 1.));
    return;
  }

  vec4 avg = vec4(0.);
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      ivec2 pos = ivec2(2 * gl_GlobalInvocationID.x + i,
                        2 * gl_GlobalInvocationID.y + j);
      vec2 sample_pos = vec2(pos) + 0.5;
      vec4 rgbo = vec4(texture(input_rgb, sample_pos).rgb, 1.0);
      float y = (transpose(push.rgb_to_yrb) * rgbo).r;
      imageStore(output_y, pos, vec4(y, 1., 1., 1.));
      avg += rgbo;
    }
  }
  ivec2 pos = ivec2(gl_GlobalInvocationID.xy);
  vec2 sample_pos = vec2(2 * pos + 0.5) + 0.5;
  //   vec4 rgbo = vec4(texture(input_rgb, sample_pos).rgb, 1.0);
  vec4 rgbo = avg / 4;
  vec2 vu = (transpose(push.rgb_to_yrb) * rgbo).bg;
  imageStore(output_vu, pos, vec4(vu, 1., 1.));
}
