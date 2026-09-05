<script lang="ts">
  import { tick } from 'svelte';
  import { Cloud, Copy, Eye, EyeOff, RefreshCw, ShieldCheck, Trash2 } from '@lucide/svelte';
  import ViewHeader from './ViewHeader.svelte';
  import { generateSyncRecoveryKey, parseSyncRecoveryKey } from '../../auth/browserSync';
  import { authenticatorVault as vault } from '../../state/authenticator.svelte';
  import { tr, type MessageKey } from '../../i18n/messages';

  interface Props {
    onclose: () => void;
    onprotect: () => void;
  }

  const ERROR_MESSAGES = {
    unavailable: 'syncUnavailable',
    passwordRequired: 'syncProtectionRequired',
    invalidKey: 'syncWrongKey',
    notFound: 'syncNoData',
    quota: 'syncQuota',
    invalidData: 'syncInvalidData',
    storage: 'syncFailed'
  } as const satisfies Record<Exclude<typeof vault.syncError, ''>, MessageKey>;

  let { onclose, onprotect }: Props = $props();
  let mode = $state<'idle' | 'create' | 'join'>('idle');
  let recoveryKey = $state('');
  let keySaved = $state(false);
  let showKey = $state(false);
  let copied = $state(false);
  let working = $state(false);
  let confirmation = $state<'stop' | 'delete' | null>(null);
  let localError = $state<MessageKey | null>(null);
  let keyInput = $state<HTMLInputElement | undefined>();

  const pending = $derived(working || vault.busy || vault.syncStatus === 'syncing');
  const errorMessage = $derived(
    localError ? tr(localError) : vault.syncError ? tr(ERROR_MESSAGES[vault.syncError]) : ''
  );
  const hasHotp = $derived(vault.accounts.some((account) => account.type === 'hotp'));
  const statusLabel = $derived(
    vault.syncStatus === 'syncing' ? tr('syncSyncing')
      : vault.syncStatus === 'pending' ? tr('syncPending')
      : vault.syncStatus === 'error' ? tr('syncErrorStatus')
      : tr('syncReady')
  );

  async function selectMode(next: 'idle' | 'create' | 'join') {
    localError = null;
    copied = false;
    keySaved = false;
    recoveryKey = '';
    try {
      if (next === 'create') recoveryKey = generateSyncRecoveryKey();
      mode = next;
      if (next === 'join') {
        await tick();
        keyInput?.focus();
      }
    } catch {
      localError = 'syncFailed';
    }
  }

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    if (pending || (mode === 'create' && !keySaved)) return;
    localError = null;
    let key: string;
    try {
      key = parseSyncRecoveryKey(recoveryKey);
    } catch {
      localError = 'syncWrongKey';
      return;
    }
    working = true;
    try {
      await vault.startBrowserSync(key, mode === 'join');
      if (vault.syncEnabled) {
        recoveryKey = '';
        keySaved = false;
        mode = 'idle';
      }
    } finally {
      working = false;
    }
  }

  async function copyKey(key: string) {
    localError = null;
    try {
      await navigator.clipboard.writeText(key);
      copied = true;
    } catch {
      localError = 'syncKeyCopyFailed';
    }
  }

  async function disconnect() {
    if (pending || !confirmation) return;
    working = true;
    localError = null;
    try {
      if (confirmation === 'delete') await vault.deleteBrowserSync();
      else await vault.stopBrowserSync();
      if (!vault.syncEnabled) {
        confirmation = null;
        showKey = false;
        copied = false;
      }
    } finally {
      working = false;
    }
  }
</script>

<div class="flex h-full flex-col overflow-hidden">
  <ViewHeader title={tr('browserSync')} onback={onclose} />
  <div class="grow space-y-4 overflow-y-auto p-3">
    {#if !vault.syncAvailable}
      <p class="text-sm text-base-content/70">{tr('syncUnavailable')}</p>
    {:else if !vault.passwordProtected}
      <div class="space-y-3">
        <ShieldCheck size={24} class="text-base-content/60" aria-hidden="true" />
        <p class="text-sm">{tr('syncProtectionRequired')}</p>
        <button class="btn btn-block" type="button" onclick={onprotect}>{tr('setPassword')}</button>
      </div>
    {:else if vault.syncEnabled}
      <div class="space-y-1 rounded-box bg-base-200/60 p-3">
        <p class="flex items-center gap-2 text-sm font-semibold">
          <Cloud size={18} aria-hidden="true" />
          {tr('syncConnected')}
        </p>
        <p
          class={['text-xs', vault.syncStatus === 'error' || vault.syncStatus === 'pending' ? 'text-warning' : 'text-base-content/65']}
          role="status"
        >{statusLabel}</p>
      </div>
      <p class="text-xs leading-relaxed text-base-content/65">{tr('syncDeliveryHint')}</p>
      <button class="btn btn-block btn-sm" type="button" onclick={() => vault.syncNow()} disabled={pending}>
        {#if pending}
          <span class="loading loading-spinner loading-xs" aria-hidden="true"></span>
        {:else}
          <RefreshCw size={15} aria-hidden="true" />
        {/if}
        {tr('syncSyncNow')}
      </button>
      <div class="space-y-2">
        <button
          class="btn btn-ghost btn-block btn-sm h-auto min-h-8 whitespace-normal"
          type="button"
          aria-expanded={showKey}
          onclick={() => { showKey = !showKey; copied = false; }}
        >
          {#if showKey}<EyeOff size={15} aria-hidden="true" />{:else}<Eye size={15} aria-hidden="true" />{/if}
          {showKey ? tr('syncHideKey') : tr('syncShowKey')}
        </button>
        {#if showKey}
          {@render keyDisplay(vault.syncRecoveryKey)}
        {/if}
      </div>
      <p class="text-xs leading-relaxed text-base-content/65">{tr('syncScope')}</p>
      {#if hasHotp}
        <p class="rounded-box border border-warning/30 bg-warning/10 p-3 text-xs leading-relaxed">{tr('syncHotpWarning')}</p>
      {/if}
      <div class="space-y-2 border-t border-base-300 pt-3">
        {#if confirmation}
          <p class="text-xs leading-relaxed text-base-content/70">
            {confirmation === 'delete' ? tr('syncDeleteHint') : tr('syncStopHint')}
          </p>
          <div class="space-y-2">
            <button class={['btn btn-block btn-sm h-auto min-h-8 whitespace-normal', confirmation === 'delete' && 'btn-error']} type="button" onclick={disconnect} disabled={pending}>
              {confirmation === 'delete' ? tr('syncDelete') : tr('syncStopConfirm')}
            </button>
            <button class="btn btn-ghost btn-block btn-sm" type="button" onclick={() => (confirmation = null)} disabled={pending}>{tr('cancel')}</button>
          </div>
        {:else}
          <button class="btn btn-ghost btn-block btn-sm h-auto min-h-8 whitespace-normal" type="button" onclick={() => (confirmation = 'stop')} disabled={pending}>{tr('syncStop')}</button>
          <button class="btn btn-ghost btn-block btn-sm h-auto min-h-8 whitespace-normal text-error" type="button" onclick={() => (confirmation = 'delete')} disabled={pending}>
            <Trash2 size={15} aria-hidden="true" />
            {tr('syncDelete')}
          </button>
        {/if}
      </div>
    {:else}
      <p class="text-sm leading-relaxed">{tr('syncDescription')}</p>
      <p class="text-xs leading-relaxed text-base-content/65">{tr('syncRequirements')}</p>
      {#if mode === 'idle'}
        <div class="space-y-2">
          <button class="btn btn-block h-auto min-h-10 whitespace-normal" type="button" onclick={() => selectMode('create')} disabled={pending}>{tr('syncStart')}</button>
          <button class="btn btn-ghost btn-block h-auto min-h-10 whitespace-normal" type="button" onclick={() => selectMode('join')} disabled={pending}>{tr('syncConnect')}</button>
        </div>
        <p class="text-xs leading-relaxed text-base-content/65">{tr('syncScope')}</p>
      {:else}
        <form class="space-y-3" onsubmit={connect}>
          {#if mode === 'create'}
            {@render keyDisplay(recoveryKey)}
            <label class="flex cursor-pointer items-start gap-2.5 text-sm">
              <input class="checkbox checkbox-sm mt-0.5 shrink-0" type="checkbox" bind:checked={keySaved} disabled={pending} />
              <span>{tr('syncSavedKey')}</span>
            </label>
          {:else}
            <p class="text-sm leading-relaxed text-base-content/70">{tr('syncJoinHint')}</p>
            <label class="block space-y-1.5">
              <span class="text-sm font-medium">{tr('syncRecoveryKey')}</span>
              <input
                class="input w-full font-mono"
                type="password"
                bind:this={keyInput}
                bind:value={recoveryKey}
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                dir="ltr"
                disabled={pending}
                oninput={() => (localError = null)}
              />
            </label>
          {/if}
          {#if hasHotp}
            <p class="rounded-box border border-warning/30 bg-warning/10 p-3 text-xs leading-relaxed">{tr('syncHotpWarning')}</p>
          {/if}
          <button class="btn btn-block h-auto min-h-10 whitespace-normal" type="submit" disabled={pending || !recoveryKey.trim() || (mode === 'create' && !keySaved)}>
            {#if pending}<span class="loading loading-spinner loading-xs" aria-hidden="true"></span>{/if}
            {mode === 'create' ? tr('syncEnable') : tr('syncConnect')}
          </button>
          <button class="btn btn-ghost btn-block btn-sm" type="button" onclick={() => selectMode('idle')} disabled={pending}>{tr('cancel')}</button>
        </form>
      {/if}
    {/if}
    {#if errorMessage}
      <p class="rounded-box border border-error/30 bg-error/5 p-3 text-sm text-error" role="alert">{errorMessage}</p>
    {/if}
  </div>
</div>

{#snippet keyDisplay(key: string)}
  <div class="space-y-2 rounded-box border border-base-300 p-3">
    <label class="block space-y-1.5">
      <span class="text-sm font-medium">{tr('syncRecoveryKey')}</span>
      <textarea
        class="textarea w-full resize-none font-mono text-xs"
        rows="3"
        readonly
        value={key}
        dir="ltr"
        spellcheck="false"
        onclick={(event) => event.currentTarget.select()}
      ></textarea>
    </label>
    <button class="btn btn-block btn-sm" type="button" onclick={() => copyKey(key)}>
      <Copy size={14} aria-hidden="true" />
      {copied ? tr('copied') : tr('copy')}
    </button>
    <p class="text-xs leading-relaxed text-base-content/65">{tr('syncRecoveryHint')}</p>
  </div>
{/snippet}
