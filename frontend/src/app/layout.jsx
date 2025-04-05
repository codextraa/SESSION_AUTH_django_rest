import { headers } from 'next/headers';
import '@/styles/globals.css';

export const metadata = {
  title: 'SESSION Auth',
  description: 'SESSION Auth',
};

export default async function RootLayout({ children }) {
  const nonce = (await headers()).get('X-CSP-Nonce');

  return (
    <html lang="en">
      <head>
        <meta name="csp-nonce" content={nonce} />
        <script
          nonce={nonce}
          dangerouslySetInnerHTML={{
            __html: `
                (function() {
                  // Wait for DOM to load to ensure all scripts are present
                  document.addEventListener('DOMContentLoaded', function() {
                    var scripts = document.querySelectorAll('script:not([nonce])');
                    scripts.forEach(function(script) {
                      script.setAttribute('nonce', '${nonce}');
                    });
                  });
                })();
              `,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
