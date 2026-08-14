import LoginForm from "@/components/forms/LoginForm";
import { SocialErrorPageProps } from "@/types/authTypes";

export default async function LoginPage({
  searchParams,
}: SocialErrorPageProps) {
  const params = await searchParams;
  const initialError = params.error || "";

  return (
    <div className="w-full min-h-screen flex flex-col gap-[40px] items-center bg-[#E7E7E7] px-4 py-8 md:py-16 selection:bg-[#263775] selection:text-white">
      <h1 className="font-['Merriweather'] font-bold text-3xl text-[#000000] text-center">
        Login
      </h1>
      <div className="w-full max-w-[540px] flex flex-col items-center justify-center">
        <LoginForm initialSocialError={initialError} />
      </div>
    </div>
  );
}
