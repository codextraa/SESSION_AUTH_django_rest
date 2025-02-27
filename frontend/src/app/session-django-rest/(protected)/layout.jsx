import '@/styles/globals.css';
import Navbar from '@/components/Navbar/Navbar';


export const metadata = {
  title: 'SESSION Auth',
  description: 'SESSION Auth',
}

export default function RootLayout({ children }) {
  return (
    <>
      <Navbar />
      {children}
    </>
  );
};