import React from "react";
import OTPVerificationForm from "@/components/forms/OTPVerificationForm";

export default function OTPVerificationPage() {
  return (
    <main className="w-full min-h-screen bg-[#E7E7E7] flex flex-col items-center justify-center px-4 selection:bg-blue-200">
      <div className="flex flex-col items-center w-full max-w-[1280px]">
        {/* Main Title Section */}
        <h1 className="font-['Merriweather'] font-bold text-[30px] leading-[38px] text-black text-center mb-10">
          OTP Verification
        </h1>

        <OTPVerificationForm />
      </div>
    </main>
  );
}
