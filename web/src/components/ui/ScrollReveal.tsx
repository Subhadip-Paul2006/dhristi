import React, { type ReactNode, useRef } from "react";
import { motion, useInView, type Variants } from "framer-motion";
import "./ScrollReveal.css";

interface ScrollRevealProps {
 children: ReactNode;
 direction?: "up" | "down" | "left" | "right" | "fade";
 duration?: number;
 delay?: number;
 stagger?: number;
 threshold?: number;
 once?: boolean;
 className?: string;
}

const DIRECTION_VARIANTS: Record<string, Variants> = {
 up: {
 hidden: { opacity: 0, y: 40 },
 visible: { opacity: 1, y: 0 },
 },
 down: {
 hidden: { opacity: 0, y: -40 },
 visible: { opacity: 1, y: 0 },
 },
 left: {
 hidden: { opacity: 0, x: -40 },
 visible: { opacity: 1, x: 0 },
 },
 right: {
 hidden: { opacity: 0, x: 40 },
 visible: { opacity: 1, x: 0 },
 },
 fade: {
 hidden: { opacity: 0 },
 visible: { opacity: 1 },
 },
};

export default function ScrollReveal({
 children,
 direction = "up",
 duration = 0.6,
 delay = 0,
 stagger = 0,
 threshold = 0.15,
 once = true,
 className = "",
}: ScrollRevealProps) {
 const ref = useRef<HTMLDivElement>(null);
 const isInView = useInView(ref, { once, amount: threshold });

 const variants = DIRECTION_VARIANTS[direction] || DIRECTION_VARIANTS.up;

 const containerVariants: Variants = {
 hidden: {},
 visible: {
 transition: {
 staggerChildren: stagger,
 delayChildren: delay,
 },
 },
 };

 return (
 <motion.div
 ref={ref}
 className={`scroll-reveal ${className}`}
 variants={containerVariants}
 initial="hidden"
 animate={isInView ? "visible" : "hidden"}
 >
 {stagger > 0 && React.Children.map(children, (child, i) => (
 <motion.div key={i} variants={variants} transition={{ duration, ease: [0.16, 1, 0.3, 1] }}>
 {child}
 </motion.div>
 ))}
 {stagger === 0 && (
 <motion.div variants={variants} transition={{ duration, delay, ease: [0.16, 1, 0.3, 1] }}>
 {children}
 </motion.div>
 )}
 </motion.div>
 );
}
