const targetUrl = 'http://localhost:30000';

const PROXY_CONFIG = [
  {
    context: ["/api"],
    target: targetUrl,
    secure: false,
    changeOrigin: true,
  }
];

module.exports = PROXY_CONFIG;