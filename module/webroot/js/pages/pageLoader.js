import { exec, fullScreen, toast } from '../kernelsu.js'

import { loadNavbar, setNavbar, whichCurrentPage } from './navbar.js'

/* INFO: Prototypes */
import utils from './utils.js'

const head = document.getElementsByTagName('head')[0]

export const allPages = [
  'home',
  'actions',
  'settings'
]

const loadedPageView = []
/* INFO: Direct assignment would link both arrays. We do not want that. */
const sufferedUpdate = [ ...allPages ]
const pageReplacements = allPages.reduce((obj, pageId) => {
  obj[pageId] = []

  return obj
}, {})

async function loadHTML(pageId) {
  return fetch(`js/pages/${pageId}/index.html`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
}

async function hotReloadStrings(html, pageId) {
  const strings = await getStrings(pageId)
  if (!strings) return html

  pageReplacements[pageId].forEach((replacement, i) => {
    const key = replacement.key.slice(2, -2)

    const split = key.split('.')
    if (split.length === 1) {
      html = html.replace(replacement.value, strings[key])
      pageReplacements[pageId][i].value = strings[key]
    } else {
      let value = strings
      split.forEach((key) => {
        value = value[key]
      })

      html = html.replace(replacement.value, value)
      pageReplacements[pageId][i].value = value
    }
  })

  return html
}

async function solveStrings(html, pageId) {
  const strings = await getStrings(pageId)
  if (!strings) return html

  const regex = /{{(.*?)}}/g
  const matches = html.match(regex)

  if (!matches) return html

  try {
    matches.forEach((match) => {
      const key = match.slice(2, -2)

      const split = key.split('.')
      if (split.length === 1) {
        html = html.replace(match, strings[key])
        pageReplacements[pageId].push({ key: match, value: strings[key] })
      } else {
        let value = strings
        split.forEach((key) => {
          value = value[key]
        })

        html = html.replace(match, value)
        pageReplacements[pageId].push({ key: match, value: value })
      }
    })
  } catch (e) {
    toast(`Failed to load ${localStorage.getItem('language') || 'en_US'} strings. Entering safe mode.`)
  }

  /* INFO: Perform navbar string replacement */
  document.getElementById('nav_home_title').innerHTML = strings.navbar.home
  document.getElementById('nav_actions_title').innerText = strings.navbar.actions
  document.getElementById('nav_settings_title').innerText = strings.navbar.settings

  return html
}

async function getPageScripts(pageId) {
  return fetch(`js/pages/${pageId}/pageScripts`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
  }

async function hasSpecificCSS(pageId) {
  return fetch(`js/pages/${pageId}/index.css`)
    .then(() => true)
    .catch(() => false)
}

function unuseHTML(page, pageId) {
  /* INFO: Remove all event listeners from window */
  utils.removeAllListeners()

  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Append pageId to id and classes */
    if (child.id) child.id = `page_${pageId}:${child.id}`
    if (child.classList) {
      const newClasses = []
      if (child.checked) child.classList.add(`--page_loader:checked=true`)

      for (const className of child.classList) {
        newClasses.push(`page_${pageId}:${className}`)
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    unuseHTML(child, pageId)
  })
}

async function loadPages() {
  return new Promise((resolve) => {
    /*
      INFO: Usually dynamic HTML leads to a lot of visual problems, which
              can vary from missing CSS for an extremely brief moment to
              a full page re-rendering. This is why we load all pages at
              once and then we just switch between them.
    */

    let amountLoaded = 0
    allPages.forEach(async (page) => {
      const pageHTML = await loadHTML(page)
      if (pageHTML === false) {
        toast('Error loading page')

        return;
      }

      const pageJSScripts = await getPageScripts(page)
      if (pageJSScripts === false) {
        toast(`Error while loading ${page} scripts`)

        return;
      }

      const pageContent = document.getElementById('page_content')
      const pageSpecificContent = document.createElement('div')
      pageSpecificContent.id = `${page}_content`
      pageSpecificContent.innerHTML = pageHTML
      pageSpecificContent.style.display = 'none'

      pageContent.appendChild(pageSpecificContent)
      unuseHTML(pageSpecificContent, page)

      const hasCSS = await hasSpecificCSS(page)
      if (hasCSS) {
        const cssCode = document.createElement('style')
        cssCode.id = `${page}_css`
        cssCode.innerHTML = await fetch(`js/pages/${page}/index.css`)
          .then((response) => response.text())
          .then((data) => {
            return data
          })
          .catch(() => false)
        cssCode.media = 'not all'

        head.appendChild(cssCode)
      }

      pageJSScripts.split('\n').forEach((line) => {
        if (line.length === 0) return;

        const jsCode = document.createElement('script')
        jsCode.src = line
        jsCode.type = 'module'
        jsCode.id = `${page}_js`

        const first = document.getElementsByTagName('script')[0]
        if (!first) {
          head.appendChild(jsCode)

          return;
        }

        first.parentNode.insertBefore(jsCode, first)
      })

      const pageJS = import(`./${page}/index.js`)
      pageJS.then((module) => module.loadOnce())

      amountLoaded++
      if (amountLoaded === allPages.length) resolve()
    })
  })
}

function revertHTMLUnuse(page, pageId) {
  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Remove pageId from id and classes */
    if (child.id) child.id = child.id.split(`page_${pageId}:`)[1]
    if (child.classList) {
      const newClasses = []

      for (const className of child.classList) {
        newClasses.push(className.split(`page_${pageId}:`)[1])
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    revertHTMLUnuse(child, pageId)
  })
}

function applyHTMLChanges(page, pageId) {
  if (page.childNodes) page.childNodes.forEach((child) => {
    /* INFO: Remove pageId from id and classes */
    if (child.classList) {
      const newClasses = []

      for (const className of child.classList) {
        if (className.startsWith(`--page_loader:checked=true`)) {
          child.checked = true
        }

        newClasses.push(className)
      }

      child.classList = []
      for (const className of newClasses) {
        child.classList.add(className)
      }
    }

    applyHTMLChanges(child, pageId)
  })
}

export async function loadPage(pageId) {
  if (whichCurrentPage() === pageId) return false

  const currentPage = whichCurrentPage()
  if (currentPage) {
    const currentPageContent = document.getElementById(`${currentPage}_content`)
    currentPageContent.style.display = 'none'

    unuseHTML(currentPageContent, currentPage)
    document.getElementById(`${currentPage}_css`).media = 'not all'
  }

  const pageSpecificContent = document.getElementById(`${pageId}_content`)
  revertHTMLUnuse(pageSpecificContent, pageId)
  document.getElementById(`${pageId}_css`).media = 'all'

  setNavbar(pageId)

  const module = await import(`./${pageId}/index.js`)
  if (!sufferedUpdate.includes(pageId)) {
    pageSpecificContent.innerHTML = await hotReloadStrings(pageSpecificContent.innerHTML, pageId)
    applyHTMLChanges(pageSpecificContent, pageId)

    module.onceViewAfterUpdate()

    sufferedUpdate.push(pageId)
  }

  if (!loadedPageView.includes(pageId)) {
    pageSpecificContent.innerHTML = await solveStrings(pageSpecificContent.innerHTML, pageId)
    applyHTMLChanges(pageSpecificContent, pageId)

    module.loadOnceView()

    loadedPageView.push(pageId)
  } else {
    applyHTMLChanges(pageSpecificContent, pageId)
  }

  module.load()

  pageSpecificContent.style.display = 'block'
}

function getMiniPage(miniPageId) {
  return fetch(`js/pages/${whichCurrentPage()}/minipages/${miniPageId}.html`)
    .then((response) => response.text())
    .then((data) => {
      return data
    })
    .catch(() => false)
}

export async function loadMiniPage(miniPageId, unloadCb) {
  const minipage_html = await getMiniPage(miniPageId)
  if (!minipage_html) {
    toast('Error loading minipage')

    return;
  }

  const page_content = document.getElementById('page_content')
  const navbar = document.getElementById('navbar')
  const navbar_support_div = document.getElementById('navbar_support_div')

  page_content.style.transition = navbar.style.transition = 'filter 0.3s'
  page_content.style.filter = navbar.style.filter = 'blur(10px)'
  /* INFO: Not allow it to interact with the page, just click to close */
  page_content.style.pointerEvents = navbar_support_div.style.pointerEvents = 'none'

  window.onceTrueEvent('click', (event) => {
    if (utils.isDivOrInsideDiv(event.target, 'minipage_content')) return;

    const minipage_content = document.getElementById('minipage_content')
    minipage_content.style.animation = 'fade-out 0.2s'

    page_content.style.transition = navbar.style.transition = 'filter 0.2s'
    page_content.style.filter = navbar.style.filter = null
    page_content.style.pointerEvents = navbar_support_div.style.pointerEvents = null

    setTimeout(() => {
      minipage_content.style.cssText = null
      minipage_content.innerHTML = null

      page_content.style.transition = navbar.style.transition = null
    }, 200)

    unloadCb()

    return true
  })

  const minipage_content = document.getElementById('minipage_content')
  minipage_content.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 1;
    background: none;
    animation: fade-in 0.3s;
  `

  minipage_content.innerHTML = `
    <div class="dim" style="padding: 20px; border-radius: 10px; width: 80vw;">
      <div class="dim" style="border-radius: 10px;">
        ${minipage_html}
      </div>
    </div>
  `
}

export async function reloadPage() {
  const pageId = whichCurrentPage()

  const pageSpecificContent = document.getElementById(`${pageId}_content`)
  pageSpecificContent.innerHTML = await solveStrings(await loadHTML(pageId), pageId)

  /* INFO: When reloading the page, due to the way the HTML is reloaded, the JavaScript
             listeners are lost, so we need to reapply them to ensure everything works. */
  utils.reapplyListeners()
}

export function getStrings(pageId) {
  return fetch(`lang/${localStorage.getItem('language') || 'en_US'}.json`)
    .then((response) => response.json())
    .then((data) => {
      return {
        ...data.pages[pageId],
        ...data.globals,
        navbar: {
          home: data.pages.home.title,
          actions: data.pages.actions.title,
          settings: data.pages.settings.title
        }
      }
    })
    .catch(() => false)
}

export function setLanguage(langId) {
  localStorage.setItem('language', langId)

  sufferedUpdate.length = 0
}

(async () => {
  await loadPages()

  let webui_config = await exec('cat /data/adb/treat_wheel/webui_config')
  if (webui_config.errno !== 0) {
    toast('Error getting WebUI\'s config of Treat Wheel!')

    return;
  }

  webui_config = webui_config.stdout

  const WebUIConfig = {
    disableFullscreen: false
  }

  webui_config.split('\n').forEach((line) => {
    if (line.startsWith('disable_fullscreen=')) WebUIConfig.disableFullscreen = line.split('=')[1] === 'true'
  })

  if (!WebUIConfig.disableFullscreen) fullScreen(true)

  loadPage('home')
  loadNavbar()
})()
