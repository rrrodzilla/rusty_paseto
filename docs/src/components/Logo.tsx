export function Logo(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 140 24" aria-hidden="true" {...props}>
      <text
        x="0"
        y="18"
        className="fill-accent-500 dark:fill-accent-400"
        style={{
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
          fontSize: '18px',
          fontWeight: 700,
        }}
      >
        rusty_paseto
      </text>
    </svg>
  )
}
