import LoginForm from "@/components/forms/LoginForm";

export default async function LoginPage() {
  return (
    <div className="w-full min-h-screen flex flex-col gap-[40px] items-center bg-[#E7E7E7] px-4 py-8 md:py-16 selection:bg-[#263775] selection:text-white">
      <h2 className="font-['Merriweather'] font-bold text-3xl text-[#000000] text-center">
        Login
      </h2>
      <div className="w-full max-w-[540px] flex flex-col items-center justify-center">
        <LoginForm />
      </div>
    </div>
  );
}
