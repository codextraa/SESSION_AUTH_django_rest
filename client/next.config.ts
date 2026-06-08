import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // output: "standalone",
  reactCompiler: true,

  allowedDevOrigins: process.env.ALLOWED_DEV_ORIGINS
    ? process.env.ALLOWED_DEV_ORIGINS.split(",")
    : ["localhost"],

  images: {
    dangerouslyAllowLocalIP: process.env.NODE_ENV === "development",
    remotePatterns: [
      {
        protocol: "https",
        hostname: process.env.NEXTJS_IMAGE_HOST || "localhost",
      },
      {
        protocol: "https",
        hostname: "lh3.googleusercontent.com",
      },
      {
        protocol: "https",
        hostname: "platform-lookaside.fbsbx.com",
      },
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
      },
      {
        protocol: "https",
        hostname:
          "codextra-media-065148239936-ap-south-1-an.s3.ap-south-1.amazonaws.com",
        port: "",
        pathname: "/**",
      },
    ],
    localPatterns: [
      {
        pathname: "/real-estate/**",
      },
      {
        pathname: "/assets/**",
      },
    ],
  },

  experimental: {
    serverActions: {
      bodySizeLimit: 10 * 1024 * 1024, // 10 MB
    },
  },
};

export default nextConfig;
