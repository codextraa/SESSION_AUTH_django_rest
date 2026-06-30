"use client";
import Image from "next/image";
import { useEffect, useState } from "react";

const updateAlertIcon = "/assets/update-alert-icon.svg";

interface UpdateAlertProps {
  alert: boolean;
  message: string | object;
}

export default function UpdateAlert({ alert, message }: UpdateAlertProps) {
  const [isAlertVisible, setIsAlertVisible] = useState<boolean>(false);
  const [isExiting, setIsExiting] = useState<boolean>(false);

  let messageResponse = "An error occurred";

  if (typeof message === "string") {
    messageResponse = message;
  } else if (message && typeof message === "object") {
    if ("detail" in message && typeof message.detail === "string") {
      messageResponse = message.detail;
    } else if ("general" in message && typeof message.general === "string") {
      messageResponse = message.general;
    } else if ("error" in message && typeof message.error === "string") {
      messageResponse = message.error;
    }
  }

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
      }, 300); // Matches the 0.3s exit animation duration
    }

    return () => clearTimeout(exitTimer);
  }, [alert, isAlertVisible]);

  return (
    <>
      {/* Injecting custom keyframes directly to keep Tailwind config clean */}
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

      {isAlertVisible && (
        <div
          className={`
            fixed z-[600] left-1/2 flex flex-row items-center whitespace-nowrap
            bg-[#ffeedb] border border-[#d97706] text-[#d97706] font-['Old_Standard_TT',serif] font-bold leading-none text-center
            
            /* Responsive Dimensions & Padding */
            top-[25px] xl:top-[40px] sm:top-[25px] min-[350px]:max-[550px]:top-[35px]
            h-[30px] sm:h-[25px]
            px-[7px] sm:px-[5px]
            gap-[10px] sm:gap-[5px]
            rounded-[10px] sm:rounded-[8px]
            text-[18px] sm:text-[16px]
            
            /* Animation Trigger */
            ${isExiting ? "animate-slide-out" : "animate-slide-in"}
          `}
        >
          <div className="w-[16px] h-[15px] sm:w-[14px] sm:h-[13px] flex items-center justify-center">
            <Image
              src={updateAlertIcon}
              alt="Warning Icon"
              width={20}
              height={20}
              className="w-full h-full object-contain"
            />
          </div>
          <span>{messageResponse}</span>
        </div>
      )}
    </>
  );
}
