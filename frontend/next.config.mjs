/** @type {import('next').NextConfig} */
const nextConfig = {
  // Surface TypeScript errors at build time. The frontend is a thin client;
  // type errors here usually indicate a real contract drift with the backend.
  typescript: {
    ignoreBuildErrors: false,
  },
  images: {
    unoptimized: true,
  },
}

export default nextConfig
