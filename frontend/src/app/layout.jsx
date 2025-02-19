import '@/styles/globals.css';


export const metadata = {
  title: 'SESSION Auth',
  description: 'SESSION Auth',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
};