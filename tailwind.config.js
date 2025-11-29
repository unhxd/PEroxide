/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      colors: {
        rust: {
          50: '#fff5f0',
          100: '#ffe8db',
          200: '#ffd1b8',
          300: '#ffb088',
          400: '#ff8a5b',
          500: '#f97316',
          600: '#d65d0e',
          700: '#b34309',
          800: '#92400e',
          900: '#78350f',
        },
      },
    },
  },
  plugins: [],
};
