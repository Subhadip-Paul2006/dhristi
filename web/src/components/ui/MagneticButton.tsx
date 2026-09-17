import { useRef, useState, useEffect, type ReactNode } from "react";
import { motion, useSpring, useTransform } from "framer-motion";
import "./MagneticButton.css";

interface MagneticButtonProps {
 children: ReactNode;
 onClick?: () => void;
 href?: string;
 variant?: "primary" | "outline" | "ghost";
 size?: "sm" | "md" | "lg";
 className?: string;
}

export default function MagneticButton({
 children,
 onClick,
 href,
 variant = "primary",
 size = "md",
 className = "",
}: MagneticButtonProps) {
 const ref = useRef<HTMLDivElement>(null);
 const [isHovering, setIsHovering] = useState(false);

 const x = useSpring(0, { stiffness: 300, damping: 20 });
 const y = useSpring(0, { stiffness: 300, damping: 20 });

 useEffect(() => {
 const el = ref.current;
 if (!el) return;

 const handleMouseMove = (e: MouseEvent) => {
 const rect = el.getBoundingClientRect();
 const centerX = rect.left + rect.width / 2;
 const centerY = rect.top + rect.height / 2;
 const deltaX = (e.clientX - centerX) * 0.15;
 const deltaY = (e.clientY - centerY) * 0.15;

 const maxDist = 120;
 const dist = Math.sqrt(deltaX ** 2 + deltaY ** 2);
 if (dist < maxDist) {
 x.set(deltaX);
 y.set(deltaY);
 } else {
 x.set(0);
 y.set(0);
 }
 };

 const handleMouseLeave = () => {
 x.set(0);
 y.set(0);
 };

 el.addEventListener("mousemove", handleMouseMove);
 el.addEventListener("mouseleave", handleMouseLeave);

 return () => {
 el.removeEventListener("mousemove", handleMouseMove);
 el.removeEventListener("mouseleave", handleMouseLeave);
 };
 }, [x, y]);

 const translateX = useTransform(x, [-100, 100], [-10, 10]);
 const translateY = useTransform(y, [-100, 100], [-10, 10]);

 const Tag = href ? "a" : "button";
 const innerRef = useRef<HTMLAnchorElement | HTMLButtonElement>(null);

 const handleClick = () => {
 if (onClick) onClick();
 };

 const sizeClasses = {
 sm: "magnetic-btn--sm",
 md: "magnetic-btn--md",
 lg: "magnetic-btn--lg",
 };

 return (
 <motion.div
 ref={ref}
 className={`magnetic-btn-wrapper ${className}`}
 style={{ x: translateX, y: translateY }}
 onHoverStart={() => setIsHovering(true)}
 onHoverEnd={() => setIsHovering(false)}
 >
 <Tag
 ref={innerRef as any}
 href={href}
 onClick={handleClick}
 className={`magnetic-btn magnetic-btn--${variant} ${sizeClasses[size]} ${isHovering ? "magnetic-btn--hovering" : ""}`}
 >
 <span className="magnetic-btn__content">{children}</span>
 <span className="magnetic-btn__ripple" />
 </Tag>
 </motion.div>
 );
}
