// SPDX-FileCopyrightText: 2017-2020 Magenta ApS
// SPDX-License-Identifier: MPL-2.0

import Vue from 'vue'
import Router from 'vue-router'
import App from './App'
import router from './router'
import i18n from './i18n.js'
import VueShortKey from 'vue-shortkey'
import store from './store'
import { sync } from 'vuex-router-sync'
import VueSplit from 'vue-split-panel'
import FlagIcon from 'vue-flag-icon'
import './vee.js'
import '@babel/polyfill'
import './icons.js'
import 'bootstrap/dist/css/bootstrap.css'
import './assets/css/global.css'
import 'moment/locale/da'  // TODO: do we need to load other locales?

import '@/views/employee/install'
import '@/views/organisation/install'
import '@/modules/install'
import Keycloak from 'keycloak-js'

sync(store, router)

Vue.config.productionTip = false

function app() {
  Vue.use(VueShortKey, { prevent: ['input', 'textarea'] })
  Vue.use(VueSplit)
  Vue.use(FlagIcon)
  Vue.use(Router)

  new Vue({
    router,
    store,
    i18n,
    render: h => h(App)
  }).$mount('#app')
}

const keycloakJson = window.location.origin + '/service/keycloak.json'
let keycloak = {}

fetch(keycloakJson, {
  method: 'HEAD'
}).then(response => {
  if (response.status === 404) {
    console.log('Authentication is disabled; starting vue app..')
    app()
  } else {
    console.log(`Authentication is enabled (keycloak.json ${response.status}); initialising keycloak..`)
    keycloak = Keycloak(keycloakJson)

    keycloak.init({ onLoad: 'login-required' }).then((auth) => {
      if (!auth) {
        window.location.reload();
      } else {
        console.log("Authenticated")
        app();
      }

      // Token refresh
      setInterval(() => {
        keycloak.updateToken(15).then((refreshed) => {
          if (refreshed) {
            console.debug('Token refreshed')
            console.debug(keycloak.tokenParsed)
          } else {
            console.debug('Token not refreshed, valid for '
              + Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds')
          }
        }).catch(() => {
          console.error('Failed to refresh token')
        });
      }, 5000)
    }).catch(() => {
      console.error("Authenticated Failed")
    });
  }
}).catch(() => {
  console.error('Error fetching keycloak.json')
})

export default keycloak
