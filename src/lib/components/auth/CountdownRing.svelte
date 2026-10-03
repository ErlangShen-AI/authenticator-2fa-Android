<script lang="ts">
  interface Props {
    remaining: number;
    period: number;
    showSeconds?: boolean;
  }

  let { remaining, period, showSeconds = false }: Props = $props();

  const CENTER = 12;
  const RADIUS = 10.75;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

  const fraction = $derived(period > 0 ? Math.max(0, Math.min(1, remaining / period)) : 0);
  const expiring = $derived(remaining <= 5);
  const dashOffset = $derived(CIRCUMFERENCE * (1 - fraction));
</script>

<div
  class="relative grid size-8 shrink-0 place-items-center"
  title={`${remaining}s`}
  role="timer"
  aria-label={`${remaining} seconds remaining`}
>
  <svg class="size-8" viewBox="0 0 24 24" aria-hidden="true">
    <circle
      cx={CENTER}
      cy={CENTER}
      r={RADIUS}
      fill="none"
      stroke-width="2.5"
      style="stroke: color-mix(in oklab, var(--color-base-content) 12%, transparent)"
    />
    <circle
      class="auth-ring-progress"
      cx={CENTER}
      cy={CENTER}
      r={RADIUS}
      fill="none"
      stroke-width="2.5"
      stroke-linecap="round"
      stroke-dasharray={CIRCUMFERENCE}
      stroke-dashoffset={dashOffset}
      transform="rotate(-90 12 12)"
      style={expiring ? 'stroke: var(--color-error)' : 'stroke: var(--color-primary)'}
    />
  </svg>
  {#if showSeconds}
    <span
      class={[
        'absolute grid size-5 place-items-center rounded-full bg-base-100/90 text-[0.625rem] font-semibold tabular-nums shadow-sm',
        expiring ? 'text-error' : 'text-base-content/70'
      ]}
    >
      {remaining}
    </span>
  {/if}
</div>

<style>
  .auth-ring-progress {
    transition:
      stroke-dashoffset 0.45s linear,
      stroke 0.2s ease;
  }

  @media (prefers-reduced-motion: reduce) {
    .auth-ring-progress {
      transition: none;
    }
  }
</style>
