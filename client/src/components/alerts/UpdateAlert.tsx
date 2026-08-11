"use client";
import Image from "next/image";
import { useEffect, useState } from "react";

const updateAlertIcon = "/assets/update-alert-icon.svg";
const updateAlertIconRed = "/assets/update-icon-red.svg";

interface UpdateAlertProps {
  alert: boolean;
  message: string;
  isError: boolean;
}

export default function UpdateAlert({
  alert,
  message,
  isError,
}: UpdateAlertProps) {
  const [isAlertVisible, setIsAlertVisible] = useState<boolean>(false);
  const [isExiting, setIsExiting] = useState<boolean>(false);

  useEffect(() => {
    let exitTimer: NodeJS.Timeout;

    if (alert) {
      setIsAlertVisible(true);
      setIsExiting(false);
    } else if (isAlertVisible) {
      setIsExiting(true);
      exitTimer = setTimeout(() => {
        setIsAlertVisible(false);
        setIsExiting(false);
      }, 300); // Match slideOutToBottom animation duration
    }

    return () => {
      if (exitTimer) clearTimeout(exitTimer);
    };
  }, [alert, isAlertVisible]); // Removed isAlertVisible from dependencies to avoid sync loops

  if (!isAlertVisible) return null;

  return (
    <>
      <style>{`
        @keyframes slideInFromTop {
          from { opacity: 0; transform: translate(-50%, -100%); }
          to { opacity: 1; transform: translate(-50%, 0); }
        }
        @keyframes slideOutToBottom {
          from { opacity: 1; transform: translate(-50%, 0); }
          to { opacity: 0; transform: translate(-50%, -100%); }
        }
        .animate-slide-in {
          animation: slideInFromTop 0.5s ease-out forwards;
        }
        .animate-slide-out {
          animation: slideOutToBottom 0.3s ease-in forwards;
        }
      `}</style>

      <div
        className={`
          fixed z-[600] left-1/2 flex flex-row items-center whitespace-nowrap
          font-['Old_Standard_TT',serif] font-bold leading-none text-center
          top-[25px] xl:top-[40px] sm:top-[25px] min-[350px]:max-[550px]:top-[35px]
          h-[30px] sm:h-[25px]
          px-[7px] sm:px-[5px]
          gap-[10px] sm:gap-[5px]
          rounded-[10px] sm:rounded-[8px]
          text-[18px] sm:text-[16px]

          ${
            isError
              ? "bg-[#FF050526] border-2 border-[#E30202] text-[#E30202]"
              : "bg-[#ffeedb] border border-[#d97706] text-[#d97706]"
          }
          
          ${isExiting ? "animate-slide-out" : "animate-slide-in"}
        `}
      >
        <div className="w-[16px] h-[15px] sm:w-[14px] sm:h-[13px] flex items-center justify-center">
          <Image
            src={isError ? updateAlertIconRed : updateAlertIcon}
            alt={isError ? "Error Icon" : "Warning Icon"}
            width={20}
            height={20}
            className="w-full h-full object-contain"
          />
        </div>
        <span>{message}</span>
      </div>
    </>
  );
}
