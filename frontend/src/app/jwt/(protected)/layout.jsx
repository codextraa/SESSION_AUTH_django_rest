import '@/styles/globals.css';
import Navbar from '@/components/Navbar/Navbar';


export const metadata = {
  title: 'JWT Auth',
  description: 'JWT Auth',
}

export default function RootLayout({ children }) {
  return (
    <>
      <Navbar />
      {children}
    </>
  );
};