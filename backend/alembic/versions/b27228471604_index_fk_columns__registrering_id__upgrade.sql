-- SPDX-FileCopyrightText: 2022 Magenta ApS
-- SPDX-License-Identifier: MPL-2.0
CREATE INDEX IF NOT EXISTS aktivitet_attr_egenskaber_idx_aktivitet_registrering_id ON aktivitet_attr_egenskaber (aktivitet_registrering_id) WHERE aktivitet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_aktivitet_registrering_id ON aktivitet_relation (aktivitet_registrering_id) WHERE aktivitet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationenhed_attr_egenskaber_idx_organisationenhed_registrering_id ON organisationenhed_attr_egenskaber (organisationenhed_registrering_id) WHERE organisationenhed_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sag_attr_egenskaber_idx_sag_registrering_id ON sag_attr_egenskaber (sag_registrering_id) WHERE sag_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_tils_gyldighed_idx_organisationfunktion_registrering_id ON organisationfunktion_tils_gyldighed (organisationfunktion_registrering_id) WHERE organisationfunktion_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_attr_udvidelser_idx_bruger_registrering_id ON bruger_attr_udvidelser (bruger_registrering_id) WHERE bruger_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_relation_idx_bruger_registrering_id ON bruger_relation (bruger_registrering_id) WHERE bruger_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_tils_gyldighed_idx_bruger_registrering_id ON bruger_tils_gyldighed (bruger_registrering_id) WHERE bruger_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_variant_idx_dokument_registrering_id ON dokument_variant (dokument_registrering_id) WHERE dokument_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_egenskaber_idx_organisationfunktion_registrering_id ON organisationfunktion_attr_egenskaber (organisationfunktion_registrering_id) WHERE organisationfunktion_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS facet_attr_egenskaber_idx_facet_registrering_id ON facet_attr_egenskaber (facet_registrering_id) WHERE facet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_organisationfunktion_registrering_id ON organisationfunktion_relation (organisationfunktion_registrering_id) WHERE organisationfunktion_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klassifikation_attr_egenskaber_idx_klassifikation_registrering_id ON klassifikation_attr_egenskaber (klassifikation_registrering_id) WHERE klassifikation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_klassifikation_registrering_id ON klassifikation_relation (klassifikation_registrering_id) WHERE klassifikation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_udvidelser_idx_organisationfunktion_registrering_id ON organisationfunktion_attr_udvidelser (organisationfunktion_registrering_id) WHERE organisationfunktion_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS aktivitet_tils_publiceret_idx_aktivitet_registrering_id ON aktivitet_tils_publiceret (aktivitet_registrering_id) WHERE aktivitet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS aktivitet_tils_status_idx_aktivitet_registrering_id ON aktivitet_tils_status (aktivitet_registrering_id) WHERE aktivitet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_attr_egenskaber_idx_dokument_registrering_id ON dokument_attr_egenskaber (dokument_registrering_id) WHERE dokument_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_relation_idx_dokument_registrering_id ON dokument_relation (dokument_registrering_id) WHERE dokument_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_tils_fremdrift_idx_dokument_registrering_id ON dokument_tils_fremdrift (dokument_registrering_id) WHERE dokument_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS facet_relation_idx_facet_registrering_id ON facet_relation (facet_registrering_id) WHERE facet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS facet_tils_publiceret_idx_facet_registrering_id ON facet_tils_publiceret (facet_registrering_id) WHERE facet_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_attr_egenskaber_idx_indsats_registrering_id ON indsats_attr_egenskaber (indsats_registrering_id) WHERE indsats_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_relation_idx_indsats_registrering_id ON indsats_relation (indsats_registrering_id) WHERE indsats_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_tils_fremdrift_idx_indsats_registrering_id ON indsats_tils_fremdrift (indsats_registrering_id) WHERE indsats_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_tils_publiceret_idx_indsats_registrering_id ON indsats_tils_publiceret (indsats_registrering_id) WHERE indsats_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS interessefaellesskab_attr_egenskaber_idx_interessefaellesskab_registrering_id ON interessefaellesskab_attr_egenskaber (interessefaellesskab_registrering_id) WHERE interessefaellesskab_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_interessefaellesskab_registrering_id ON interessefaellesskab_relation (interessefaellesskab_registrering_id) WHERE interessefaellesskab_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS interessefaellesskab_tils_gyldighed_idx_interessefaellesskab_registrering_id ON interessefaellesskab_tils_gyldighed (interessefaellesskab_registrering_id) WHERE interessefaellesskab_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS itsystem_attr_egenskaber_idx_itsystem_registrering_id ON itsystem_attr_egenskaber (itsystem_registrering_id) WHERE itsystem_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_itsystem_registrering_id ON itsystem_relation (itsystem_registrering_id) WHERE itsystem_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS itsystem_tils_gyldighed_idx_itsystem_registrering_id ON itsystem_tils_gyldighed (itsystem_registrering_id) WHERE itsystem_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klasse_attr_egenskaber_idx_klasse_registrering_id ON klasse_attr_egenskaber (klasse_registrering_id) WHERE klasse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klasse_relation_idx_klasse_registrering_id ON klasse_relation (klasse_registrering_id) WHERE klasse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klasse_tils_publiceret_idx_klasse_registrering_id ON klasse_tils_publiceret (klasse_registrering_id) WHERE klasse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS klassifikation_tils_publiceret_idx_klassifikation_registrering_id ON klassifikation_tils_publiceret (klassifikation_registrering_id) WHERE klassifikation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS loghaendelse_attr_egenskaber_idx_loghaendelse_registrering_id ON loghaendelse_attr_egenskaber (loghaendelse_registrering_id) WHERE loghaendelse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_loghaendelse_registrering_id ON loghaendelse_relation (loghaendelse_registrering_id) WHERE loghaendelse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS loghaendelse_tils_gyldighed_idx_loghaendelse_registrering_id ON loghaendelse_tils_gyldighed (loghaendelse_registrering_id) WHERE loghaendelse_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisation_attr_egenskaber_idx_organisation_registrering_id ON organisation_attr_egenskaber (organisation_registrering_id) WHERE organisation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisation_relation_idx_organisation_registrering_id ON organisation_relation (organisation_registrering_id) WHERE organisation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisation_tils_gyldighed_idx_organisation_registrering_id ON organisation_tils_gyldighed (organisation_registrering_id) WHERE organisation_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_attr_egenskaber_idx_bruger_registrering_id ON bruger_attr_egenskaber (bruger_registrering_id) WHERE bruger_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_organisationenhed_registrering_id ON organisationenhed_relation (organisationenhed_registrering_id) WHERE organisationenhed_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationenhed_tils_gyldighed_idx_organisationenhed_registrering_id ON organisationenhed_tils_gyldighed (organisationenhed_registrering_id) WHERE organisationenhed_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sag_relation_idx_sag_registrering_id ON sag_relation (sag_registrering_id) WHERE sag_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sag_tils_fremdrift_idx_sag_registrering_id ON sag_tils_fremdrift (sag_registrering_id) WHERE sag_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_attr_egenskaber_idx_tilstand_registrering_id ON tilstand_attr_egenskaber (tilstand_registrering_id) WHERE tilstand_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_tilstand_registrering_id ON tilstand_relation (tilstand_registrering_id) WHERE tilstand_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_tils_publiceret_idx_tilstand_registrering_id ON tilstand_tils_publiceret (tilstand_registrering_id) WHERE tilstand_registrering_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_tils_status_idx_tilstand_registrering_id ON tilstand_tils_status (tilstand_registrering_id) WHERE tilstand_registrering_id IS NOT NULL;
