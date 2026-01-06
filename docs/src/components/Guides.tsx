import { Button } from '@/components/Button'
import { Heading } from '@/components/Heading'

const guides = [
  {
    href: '/installation',
    name: 'Installation',
    description: 'Get started with rusty_paseto using Cargo and feature flags.',
  },
  {
    href: '/claims',
    name: 'Claims',
    description: 'Learn about the seven PASETO claims and how to use them.',
  },
  {
    href: '/keys',
    name: 'Key Management',
    description: 'Understand symmetric and asymmetric keys for PASETO tokens.',
  },
  {
    href: '/errors',
    name: 'Error Handling',
    description: 'Handle errors gracefully with the unified Error type.',
  },
]

export function Guides() {
  return (
    <div className="my-16 xl:max-w-none">
      <Heading level={2} id="guides">
        Guides
      </Heading>
      <div className="not-prose mt-4 grid grid-cols-1 gap-8 border-t border-zinc-900/5 pt-10 sm:grid-cols-2 xl:grid-cols-4 dark:border-white/5">
        {guides.map((guide) => (
          <div key={guide.href}>
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">
              {guide.name}
            </h3>
            <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              {guide.description}
            </p>
            <p className="mt-4">
              <Button href={guide.href} variant="text" arrow="right">
                Read more
              </Button>
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
