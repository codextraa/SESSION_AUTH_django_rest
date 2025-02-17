import '@/styles/globals.css';


export const metadata = {
  title: 'JWT Auth',
  description: 'JWT Auth',
}

export default function RootLayout({ children }) {
  return (
    <>
      {children}
    </>
  );
};