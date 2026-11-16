import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Every signed-in page reads the session cookie, so pages render per request.
  // Cache Components can be adopted later, route by route.
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
