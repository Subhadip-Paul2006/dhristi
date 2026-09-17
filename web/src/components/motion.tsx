// Drishti — shared motion primitives | 11-Jul-2026
/** framer-motion helpers for the authed app chunk (Dashboard). Do NOT import
 * from the landing chunk — the landing page is CSS-only by design and must
 * not pull ~30 KB of framer-motion into its critical path. Everything
 * degrades to no-motion under prefers-reduced-motion via useReducedMotion. */
import { motion, useReducedMotion, type Variants } from "framer-motion";
import type { ReactNode } from "react";

const EASE = [0.2, 0.8, 0.2, 1] as const;

/** Fade + slide-up as the element scrolls into view (once). */
export function Reveal({
  children,
  className,
  delay = 0,
  as = "div",
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
  as?: "div" | "section" | "li" | "ol";
}) {
  const reduce = useReducedMotion();
  const MotionTag = motion[as];
  return (
    <MotionTag
      className={className}
      initial={reduce ? false : { opacity: 0, y: 24 }}
      whileInView={reduce ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.25 }}
      transition={{ duration: 0.5, ease: EASE, delay }}
    >
      {children}
    </MotionTag>
  );
}

/** Container that staggers its Stagger.Item children when it enters view. */
export function Stagger({
  children,
  className,
  as = "div",
  gap = 0.08,
}: {
  children: ReactNode;
  className?: string;
  as?: "div" | "ol" | "ul";
  gap?: number;
}) {
  const reduce = useReducedMotion();
  const MotionTag = motion[as];
  const variants: Variants = {
    hidden: {},
    visible: { transition: { staggerChildren: reduce ? 0 : gap } },
  };
  return (
    <MotionTag
      className={className}
      initial={reduce ? false : "hidden"}
      whileInView={reduce ? undefined : "visible"}
      viewport={{ once: true, amount: 0.2 }}
      variants={variants}
    >
      {children}
    </MotionTag>
  );
}

const ITEM: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45, ease: EASE } },
};

export function StaggerItem({
  children,
  className,
  as = "div",
}: {
  children: ReactNode;
  className?: string;
  as?: "div" | "li";
}) {
  const MotionTag = motion[as];
  // variants resolve from the parent Stagger; when reduced, the parent sets
  // initial={false} so items render in their final state with no animation
  return (
    <MotionTag className={className} variants={ITEM}>
      {children}
    </MotionTag>
  );
}
