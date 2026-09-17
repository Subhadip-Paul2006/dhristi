import { motion } from "framer-motion";
import React, { ReactNode } from "react";
import clsx from "clsx";

interface AuroraBackgroundProps extends React.HTMLProps<HTMLDivElement> {
  children?: ReactNode;
  showRadialGradient?: boolean;
}

export const AuroraBackground = ({
  className,
  children,
  showRadialGradient = true,
  ...props
}: AuroraBackgroundProps) => {
  return (
    <div
      className={clsx(
        "relative flex flex-col items-center justify-center bg-bg-base text-ink-primary transition-colors",
        className
      )}
      {...props}
    >
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className={clsx(
            "filter blur-[40px] opacity-20 will-change-transform",
            "absolute inset-0 w-[200%] h-full",
            "bg-[linear-gradient(100deg,rgba(0,255,102,0.03)_10%,rgba(16,185,129,0.02)_30%,rgba(0,255,102,0.03)_50%,rgba(16,185,129,0.02)_70%)]",
            "[background-size:200%,_200%]",
            showRadialGradient &&
              "[mask-image:radial-gradient(ellipse_at_50%_0%,black_30%,transparent_70%)]"
          )}
        >
          <motion.div
            initial={{ backgroundPosition: "0% 50%" }}
            animate={{ backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"] }}
            transition={{
              duration: 20,
              ease: "linear",
              repeat: Infinity,
            }}
            className="w-full h-full absolute inset-0 mix-blend-screen"
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")`,
              backgroundBlendMode: "overlay",
              opacity: 0.05,
            }}
          />
        </div>
      </div>
      {children}
    </div>
  );
};
