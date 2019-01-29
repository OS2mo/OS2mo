import removeNamespace from '@/helpers/namespaceHelper'

const NAMESPACE = 'facet'

export const Facet = {
  NAMESPACE: NAMESPACE,
  actions: {
    SET_FACET: `${NAMESPACE}/SET_FACET`
  },
  mutations: {
    SET_FACET: `${NAMESPACE}/SET_FACET`
  },
  getters: {
    GET_FACET: `${NAMESPACE}/GET_FACET`
  }
}

export const _facet = removeNamespace(`${NAMESPACE}/`, Facet)
