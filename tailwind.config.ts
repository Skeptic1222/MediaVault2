import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./client/index.html", "./client/src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        card: {
          DEFAULT: "var(--card)",
          foreground: "var(--card-foreground)",
        },
        popover: {
          DEFAULT: "var(--popover)",
          foreground: "var(--popover-foreground)",
        },
        primary: {
          DEFAULT: "var(--primary)",
          foreground: "var(--primary-foreground)",
        },
        secondary: {
          DEFAULT: "var(--secondary)",
          foreground: "var(--secondary-foreground)",
        },
        muted: {
          DEFAULT: "var(--muted)",
          foreground: "var(--muted-foreground)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-foreground)",
        },
        destructive: {
          DEFAULT: "var(--destructive)",
          foreground: "var(--destructive-foreground)",
        },
        border: "var(--border)",
        input: "var(--input)",
        ring: "var(--ring)",
        chart: {
          "1": "var(--chart-1)",
          "2": "var(--chart-2)",
          "3": "var(--chart-3)",
          "4": "var(--chart-4)",
          "5": "var(--chart-5)",
        },
        sidebar: {
          DEFAULT: "var(--sidebar)",
          foreground: "var(--sidebar-foreground)",
          primary: "var(--sidebar-primary)",
          "primary-foreground": "var(--sidebar-primary-foreground)",
          accent: "var(--sidebar-accent)",
          "accent-foreground": "var(--sidebar-accent-foreground)",
          border: "var(--sidebar-border)",
          ring: "var(--sidebar-ring)",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "Inter", "system-ui", "sans-serif"],
        serif: ["var(--font-serif)", "Georgia", "serif"],
        mono: ["var(--font-mono)", "Menlo", "monospace"],
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "fade-in": "fade-in 0.3s ease-out",
        "slide-up": "slide-up 0.3s ease-out",
        "slide-down": "slide-down 0.3s ease-out",
        "scale-in": "scale-in 0.2s ease-out",
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-up": {
          from: { transform: "translateY(100%)" },
          to: { transform: "translateY(0)" },
        },
        "slide-down": {
          from: { transform: "translateY(-100%)" },
          to: { transform: "translateY(0)" },
        },
        "scale-in": {
          from: { transform: "scale(0.95)", opacity: "0" },
          to: { transform: "scale(1)", opacity: "1" },
        },
        "pulse-glow": {
          "0%, 100%": { 
            boxShadow: "0 0 20px hsl(var(--accent) / 0.3), 0 0 40px hsl(var(--accent) / 0.1)" 
          },
          "50%": { 
            boxShadow: "0 0 30px hsl(var(--accent) / 0.5), 0 0 60px hsl(var(--accent) / 0.2)" 
          },
        },
      },
      boxShadow: {
        'vault': '0 0 20px hsl(var(--accent) / 0.3), 0 0 40px hsl(var(--accent) / 0.1)',
        'media': '0 20px 40px hsl(var(--primary) / 0.4)',
        'glass': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
        'glow-sm': '0 0 10px hsl(var(--primary) / 0.5)',
        'glow-md': '0 0 20px hsl(var(--primary) / 0.5)',
        'glow-lg': '0 0 30px hsl(var(--primary) / 0.5)',
      },
      backdropBlur: {
        xs: '2px',
      },
      typography: {
        DEFAULT: {
          css: {
            color: 'var(--foreground)',
            backgroundColor: 'var(--background)',
            'h1, h2, h3, h4, h5, h6': {
              color: 'var(--foreground)',
            },
            a: {
              color: 'var(--primary)',
              '&:hover': {
                color: 'var(--primary)',
                opacity: '0.8',
              },
            },
            code: {
              color: 'var(--foreground)',
              backgroundColor: 'var(--muted)',
              padding: '0.25rem 0.5rem',
              borderRadius: '0.25rem',
            },
            pre: {
              backgroundColor: 'var(--muted)',
              color: 'var(--foreground)',
            },
            blockquote: {
              borderLeftColor: 'var(--border)',
              color: 'var(--muted-foreground)',
            },
          },
        },
      },
      screens: {
        'xs': '475px',
        '3xl': '1600px',
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
    },
  },
  plugins: [
    require("tailwindcss-animate"), 
    require("@tailwindcss/typography"),
    // Custom plugin for vault-specific utilities
    function({ addUtilities }: any) {
      const newUtilities = {
        '.vault-glow': {
          'box-shadow': '0 0 20px hsl(var(--accent) / 0.3), 0 0 40px hsl(var(--accent) / 0.1)',
        },
        '.media-hover': {
          'transition': 'all 0.3s ease',
          '&:hover': {
            'transform': 'translateY(-4px) scale(1.02)',
            'box-shadow': '0 20px 40px hsl(var(--primary) / 0.4)',
          },
        },
        '.glass-effect': {
          'background': 'rgba(255, 255, 255, 0.05)',
          'backdrop-filter': 'blur(20px)',
          'border': '1px solid rgba(255, 255, 255, 0.1)',
        },
        '.keyboard-nav-active': {
          'outline': '2px solid var(--accent)',
          'outline-offset': '2px',
        },
      }
      
      addUtilities(newUtilities, ['responsive', 'hover'])
    }
  ],
} satisfies Config;
