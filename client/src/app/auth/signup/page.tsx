import SignupForm from "@/components/forms/SignupForm";

export default async function SignupPage() {
  return (
    <div className="w-full min-h-screen flex flex-col gap-[40px] items-center bg-[#E7E7E7] px-4 py-8 md:py-16 selection:bg-[#263775] selection:text-white">
      <h1 className="font-['Merriweather'] font-bold text-[30px] text-center text-[#000000]">
        Sign Up
      </h1>
      <div className="w-full max-w-[540px] flex flex-col items-center justify-center">
        <SignupForm />
      </div>
    </div>
  );
}
