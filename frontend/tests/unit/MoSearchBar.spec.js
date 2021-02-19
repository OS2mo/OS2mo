// SPDX-FileCopyrightText: 2017-2021 Magenta ApS
// SPDX-License-Identifier: MPL-2.0

import { createLocalVue, mount } from '@vue/test-utils'
import Vuex from 'vuex'
import VeeValidate from 'vee-validate'
import 'vue-awesome/icons/search'
import Search from '@/api/Search'
import MoSearchBar from '@/components/MoSearchBar/MoSearchBar.vue'

// Mock the `Search` module
jest.mock('@/api/Search')

describe('MoSearchBar.vue', () => {
  let wrapper, store

  beforeEach(() => {
    // Mock Vue '$t' translation function
    const $t = (msg) => msg

    // Mock Vue $route (this is read by the `MoSearchBar` component)
    const $route = { name: 'Organisation' }

    // Set up local Vue object
    const localVue = createLocalVue()
    localVue.use(Vuex)
    localVue.use(VeeValidate)

    // Set up mock Vuex store
    store = new Vuex.Store()
    store.dispatch = jest.fn()
    store.replaceState({ organisation: { uuid: '1234' } })

    wrapper = mount(MoSearchBar, {
      store,
      localVue,
      mocks: { $t, $route },
    })
  })

  it('should use `Search.organisations` in `updateItems`', async () => {
    // Search query passed to `Search.organisations`
    const query = 'my query'

    // Mock resolved value of `Search.organisations` (actual value does not matter)
    Search.organisations.mockResolvedValue(null)

    await wrapper.vm.updateItems(query)
    expect(Search.organisations).toHaveBeenCalledWith(
      store.state.organisation.uuid, query
    )
  })
})
