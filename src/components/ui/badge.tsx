import * as React from "react";
import { Slot } from "@radix-ui/react-slot@1.1.2";
import { cva, type VariantProps } from "class-variance-authority@0.7.1";

import { cn } from "./utils";

const badgeVariants = cva(
  "inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap shrink-0 [&>svg]:size-3 gap-1 [&>svg]:pointer-events-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive transition-all duration-200 overflow-hidden backdrop-blur-sm",
  {
    variants: {
      variant: {
        default:
          "border-primary/30 bg-primary/10 text-primary shadow-sm [a&]:hover:bg-primary/20",
        secondary:
          "border-secondary-foreground/30 bg-secondary text-secondary-foreground [a&]:hover:bg-secondary/90 shadow-sm",
        destructive:
          "border-destructive/30 bg-destructive/10 text-destructive shadow-sm [a&]:hover:bg-destructive/20 focus-visible:ring-destructive/20",
        outline:
          "text-foreground border-primary/20 [a&]:hover:bg-primary/5 [a&]:hover:text-primary",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "span";

  return (
    <Comp
      data-slot="badge"
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

export { Badge, badgeVariants };
