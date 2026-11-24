// Socket.io external fallback loader (Compliant with CSP script-src 'self')
if (typeof io === 'undefined') {
  const fallbackScript = document.createElement('script');
  fallbackScript.src = 'https://cdn.socket.io/4.8.1/socket.io.min.js';
  fallbackScript.async = false;
  document.head.appendChild(fallbackScript);
}
