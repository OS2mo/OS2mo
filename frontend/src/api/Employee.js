// SPDX-FileCopyrightText: 2017-2020 Magenta ApS
// SPDX-License-Identifier: MPL-2.0

import Service from './HttpCommon'
import { EventBus, Events } from '@/EventBus'
import store from '@/store'

const identfyItAssociationData = function(data) {
  
  if (Array.isArray(data) && data[0].it) {

    // Probably data for creating a new IT association
    return data.map(d => sanitizeData(d))

  } else if (data.data && data.data.it) {

    // Probably data for editing an IT association
    return sanitizeData(data.data)

  } else {

    // Nothing special. Just patch it through.
    return data

  }
}

const sanitizeData = function(data) {

  // IT association hack:
  // When creating an IT association, we must scrub the data to conform to 
  // the special API request format that is supported by the backend.
  
  let new_data = { type: "association" }
  if (data.person) {
    new_data.person = { uuid: data.person.uuid }
  }
  if (data.org_unit) {
    new_data.org_unit = { uuid: data.org_unit.uuid }
  }
  if (data.org) {
    new_data.org = { uuid: data.org.uuid }
  }
  if (data.job_function) {
    new_data.job_function = { uuid: data.job_function.uuid }
  }
  if (data.it) {
    new_data.it = { uuid: data.it.uuid }
  }
  if (data.validity) {
    new_data.validity = { from: data.validity.from, to: data.validity.to }
  }
  if (data.primary) {
    new_data.primary = { uuid: data.primary }
  }
   
  return new_data
}

export default {

  /**
   * Get engagement details for employee
   * @param {String} uuid - employee uuid
   * @see getDetail
   */
  getEngagementDetails (uuid, validity) {
    return this.getDetail(uuid, 'engagement', validity)
  },

  /**
   * Base call for getting details.
   * @param {String} uuid - employee uuid
   * @param {String} detail - Name of the detail
   * @returns {Array} A list of options for the detail
   */
  getDetail (uuid, detail, validity) {
    validity = validity || 'present'
    return Service.get(`/e/${uuid}/details/${detail}?validity=${validity}`)
      .then(response => {
        return response.data
      })
      .catch(error => {
        store.commit('log/newError', { type: 'ERROR', value: error.response })
      })
  },

  /**
   * Create a new employee
   * @param {String} uuid - employee uuid
   * @param {Array} create - A list of elements to create
   * @returns {Object} employee uuid
   */
  createEntry (create) {
    return Service.post('/details/create', create)
      .then(response => {
        EventBus.$emit(Events.EMPLOYEE_CHANGED)
        return response
      })
      .catch(error => {
        EventBus.$emit(Events.EMPLOYEE_CHANGED)
        store.commit('log/newError', { type: 'ERROR', value: error.response })
        return error.response
      })
  },

  create (create) {

    return this.createEntry(identfyItAssociationData(create))
      .then(response => {
        if (response.data.error) {
          return response.data
        }
        return response.data
      })
  },

  /**
   * Edit an employee
   * @param {String} uuid - employee uuid
   * @param {Array} edit - A list of elements to edit
   * @returns {Object} employeee uuid
   */
  edit (edit) {
    return Service.post('/details/edit', identfyItAssociationData(edit))
      .then(response => {
        EventBus.$emit(Events.EMPLOYEE_CHANGED)
        return response.data
      })
      .catch(error => {
        store.commit('log/newError', { type: 'ERROR', value: error.response.data })
        return error.response.data
      })
  }
}
