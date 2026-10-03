<script lang="ts">
  import type { Snippet } from 'svelte';
  import { pushBackLayer } from './backLayer';
  import {
    modalScrim,
    modalSurface,
    type MotionDialogPlacement
  } from './transitions';

  interface Props {
    children: Snippet;
    onclose: () => void;
    placement?: MotionDialogPlacement;
    surfaceClass?: string;
    closeLabel: string;
  }

  let {
    children,
    onclose,
    placement = 'center',
    surfaceClass = '',
    closeLabel
  }: Props = $props();
  let outroing = false;

  function closeFromCancel(event: Event) {
    event.preventDefault();
    onclose();
  }

  function closeFromEscape(event: KeyboardEvent) {
    if (outroing || event.key !== 'Escape' || event.defaultPrevented) {
      return;
    }
    event.preventDefault();
    onclose();
  }

  // Let the back gesture close this dialog before it can leave the page.
  $effect(() => {
    return pushBackLayer(() => onclose());
  });
</script>

<svelte:window onkeydown={closeFromEscape} />

<dialog
  class={['modal modal-open motion-dialog', placement === 'sheet' ? 'modal-bottom' : 'modal-middle']}
  open
  oncancel={closeFromCancel}
>
  <div
    class={['modal-box motion-dialog-surface', surfaceClass]}
    transition:modalSurface|global={{ placement }}
    onoutrostart={() => (outroing = true)}
  >
    {#if placement === 'sheet'}
      <div class="auth-sheet-grabber" aria-hidden="true"></div>
    {/if}
    {@render children()}
  </div>
  <button
    class="modal-backdrop motion-dialog-scrim"
    type="button"
    aria-label={closeLabel}
    onclick={onclose}
    transition:modalScrim|global
  ></button>
</dialog>

<style>
  .motion-dialog.modal {
    background-color: transparent;
    opacity: 1;
    transition: none;
  }

  .motion-dialog-surface.modal-box {
    position: relative;
    opacity: 1;
    transform: none;
    transform-origin: center;
    translate: 0;
    scale: 1;
    box-shadow: 0 24px 64px -16px rgb(9 12 20 / 0.35);
    transition: none;
    will-change: transform, opacity;
  }

  .modal-bottom .motion-dialog-surface {
    transform-origin: bottom center;
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
    border-top-left-radius: 1.5rem;
    border-top-right-radius: 1.5rem;
    padding-top: 0.9rem;
    padding-bottom: max(1rem, env(safe-area-inset-bottom, 0px));
  }

  .auth-sheet-grabber {
    position: absolute;
    top: 0.4rem;
    left: 50%;
    width: 2.5rem;
    height: 0.25rem;
    border-radius: 9999px;
    background: color-mix(in oklab, var(--color-base-content) 18%, transparent);
    transform: translateX(-50%);
  }

  .motion-dialog-scrim.modal-backdrop {
    border: 0;
    background-color: rgb(0 0 0 / 0.38);
    backdrop-filter: blur(2px);
    will-change: opacity;
  }

  :global(.motion-dialog:has(~ .motion-dialog)) .motion-dialog-scrim {
    visibility: hidden;
    backdrop-filter: none;
  }

  :global(.motion-dialog ~ .motion-dialog) .motion-dialog-scrim {
    opacity: 1 !important;
  }

  @media (prefers-reduced-transparency: reduce) {
    .motion-dialog-scrim.modal-backdrop {
      background-color: rgb(0 0 0 / 0.5);
      backdrop-filter: none;
    }
  }

  @media (prefers-contrast: more) {
    .motion-dialog-scrim.modal-backdrop {
      background-color: rgb(0 0 0 / 0.55);
      backdrop-filter: none;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .motion-dialog-surface.modal-box {
      transform: none;
      will-change: opacity;
    }
  }
</style>
