import { exec, toast } from '../../kernelsu.js'

import { whichCurrentPage } from '../navbar.js'
import { getStrings } from '../pageLoader.js'

globalThis.rootInfo = {
  impl: null
}

async function _isModuleDisabled() {
  let status = await exec('stat "/data/adb/modules/treat_wheel/disable"')
  if (status.errno === 0) return true

  return false
}

async function _isModuleIgnoring() {
  let state = await exec('cat /data/adb/treat_wheel/state')
  if (state.errno !== 0) {
    toast('Error getting state of Treat Wheel!')

    return;
  }

  let isIgnoring = false
  state.stdout.split('\n').forEach((line) => {
    if (line.startsWith('ignoring=')) isIgnoring = line.split('=')[1] === 'true'
  })

  return isIgnoring
}

async function _getVersion() {
  let moduleProp = await exec('cat /data/adb/modules/treat_wheel/module.prop')
  if (moduleProp.errno !== 0) {
    toast('Error getting state of Treat Wheel!')

    return;
  }

  let version = '???'
  moduleProp.stdout.split('\n').forEach((line) => {
    if (line.startsWith('version=')) version = line.split('=')[1]
  })

  return version
}

async function _usedRootImpl() {
  let providers = {
    KSU: false,
    APatch: false,
    Magisk: false
  }

  /* TODO: Use cmd to do prctl KSU detection */
  {
    /* INFO: See if /data/adb/ksud exists */
    const ksuVersion = await exec('/data/adb/ksud debug version')
    if (ksuVersion.errno === 0 && ksuVersion.stdout !== 'Kernel Version: 0') providers.KSU = true
  }

  {
    let apdExists = await exec('/data/adb/apd --help')
    if (apdExists.errno === 0) providers.APatch = true
  }

  {
    const magiskFiles = [
      '/sbin/magisk32', '/sbin/magisk64',
      '/sbin/magisk',
      '/debug_ramdisk/magisk32', '/debug_ramdisk/magisk64',
      '/debug_ramdisk/magisk'
    ]

    for (let i = 0; i < magiskFiles.length; i++) {
      const fileExists = await exec(`${magiskFiles[i]} -V`)
      if (fileExists.errno === 0) {
        providers.Magisk = true

        break
      }
    }
  }

  /* TODO: New warning if it's multiple */
  if ((providers.KSU) + (providers.APatch) + (providers.Magisk) > 1) return 'Multiple'
  if (providers.KSU) return 'KernelSU'
  if (providers.APatch) return 'APatch'
  if (providers.Magisk) return 'Magisk'

  return false
}

export async function loadOnce() {

}

let lastStrings = null

export async function loadOnceView() {
  document.getElementById('version_code').innerHTML = await _getVersion()

  const strings = await getStrings(whichCurrentPage())

  let root_impl = globalThis.rootInfo.impl = await _usedRootImpl()
  if (!root_impl) root_impl = strings.unknown
  if (root_impl === 'Multiple') root_impl = strings.rootImpls.multiple

  document.getElementById('root_impl').innerHTML = root_impl
}

export async function onceViewAfterUpdate() {
  /* INFO: Update translations */
  const strings = await getStrings(whichCurrentPage())

  const tw_state = document.getElementById('tw_state')
  if (tw_state.innerHTML === lastStrings.workingModes.disabled)
    tw_state.innerHTML = strings.workingModes.disabled
  else if (tw_state.innerHTML === lastStrings.workingModes.unknown)
    tw_state.innerHTML = strings.workingModes.unknown
  else if (tw_state.innerHTML === lastStrings.workingModes.sigcheckFailed)
    tw_state.innerHTML = strings.workingModes.sigcheckFailed
  else if (tw_state.innerHTML === lastStrings.workingModes.ignoring)
    tw_state.innerHTML = strings.workingModes.ignoring
  else if (tw_state.innerHTML === lastStrings.workingModes.crashed)
    tw_state.innerHTML = strings.workingModes.crashed
  else if (tw_state.innerHTML === lastStrings.workingModes.working)
    tw_state.innerHTML = strings.workingModes.working

  lastStrings = strings
}

export async function load() {
  if (lastStrings !== null) return;

  const rootCss = document.querySelector(':root')
  const tw_state = document.getElementById('tw_state')

  const status = await exec('cat /data/adb/treat_wheel/status')

  const isIgnoring = await _isModuleIgnoring()

  const strings = await getStrings(whichCurrentPage())
  lastStrings = strings

  if (await _isModuleDisabled()) {
    tw_state.innerHTML = strings.workingModes.disabled

    rootCss.style.setProperty('--bright', '#808080')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/warn.svg">'
  } else if (status.errno !== 0) {
    tw_state.innerHTML = strings.workingModes.unknown

    rootCss.style.setProperty('--bright', '#766000')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/mark.svg">'
  } else if (status.stdout === 'version_expired') {
    tw_state.innerHTML = strings.workingModes.testVersionExpired

    rootCss.style.setProperty('--bright', '#ff0000')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/warn.svg">'
  } else if (status.stdout === 'kang_detected') {
    tw_state.innerHTML = strings.workingModes.improperAttribution

    rootCss.style.setProperty('--bright', '#ff0000')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/warn.svg">'
  } else if (status.stdout === 'sigcheck_failed') {
    tw_state.innerHTML = strings.workingModes.sigcheckFailed

    rootCss.style.setProperty('--bright', '#ff0000')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/warn.svg">'
  } else if (isIgnoring) {
    tw_state.innerHTML = strings.workingModes.ignoring

    rootCss.style.setProperty('--bright', '#808080')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/mark.svg">'
  } else if (status.stdout === 'crashed') {
    tw_state.innerHTML = strings.workingModes.crashed

    rootCss.style.setProperty('--bright', '#766000')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/warn.svg">'
  } else {
    tw_state.innerHTML = strings.workingModes.working

    rootCss.style.setProperty('--bright', '#3a4857')
    tw_icon_state.innerHTML = '<img class="brightc" src="assets/tick.svg">'
  }

  /* INFO: This hides the throbber screen */
  loading_screen.style.display = 'none'
}
