import { loadMiniPage, reloadPage, setLanguage } from '../pageLoader.js'
import utils from '../utils.js'

import { exec, fullScreen, toast } from '../../kernelsu.js'

function _writeState(ConfigState) {
  let config = ''

  if (ConfigState.disableFullscreen) config += 'disable_fullscreen=true\n'

  return exec(`echo "${config}" > /data/adb/treat_wheel/webui_config`)
}

export async function loadOnce() {

}

export async function loadOnceView() {

}

export async function onceViewAfterUpdate() {

}

export async function load() {
  let ConfigState = {
    disableFullscreen: false
  }

  if (!globalThis.loadedWebUIConfigState) {
    let webui_config = await exec('cat /data/adb/treat_wheel/webui_config')
    if (webui_config.errno !== 0) {
      toast('Error getting WebUI\'s config of Treat Wheel!')

      return;
    }

    webui_config = webui_config.stdout

    webui_config.split('\n').forEach((line) => {
      if (line.startsWith('disable_fullscreen=')) ConfigState.disableFullscreen = line.split('=')[1] === 'true'
    })
  }

  if (globalThis.loadedModuleConfigState) {
    ConfigState.disableFullscreen = tw_webui_fullscreen_switch.checked
  }

  globalThis.loadedWebUIConfigState = true

  const lang_page_toggle = document.getElementById('lang_page_toggle')
  if (ConfigState.disableFullscreen) lang_page_toggle.checked = true

  utils.addListener(lang_page_toggle, 'click', async () => {
    function setLanguageCb(event) {
      if (event.target === undefined || !event.target.id.startsWith('language:')) return;

      const language = event.target.id.split(':')[1]

      setLanguage(language)
      reloadPage()

      return true
    }

    loadMiniPage('language', () => {
      utils.removeListener(window, 'click', setLanguageCb)
    })

    utils.addListener(window, 'click', setLanguageCb)
  })

  const tw_webui_fullscreen_switch = document.getElementById('tw_webui_fullscreen_switch')
  if (ConfigState.disableFullscreen) tw_webui_fullscreen_switch.checked = true

  utils.addListener(tw_webui_fullscreen_switch, 'click', () => {
    /* INFO: This is swapped, as it meant to disable the fullscreen */
    ConfigState.disableFullscreen = !ConfigState.disableFullscreen
    _writeState(ConfigState)

    fullScreen(!ConfigState.disableFullscreen)
  })
}