-- SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
-- SPDX-License-Identifier: MPL-2.0

-- rel_maal_urn_isolated
-- rel_mmal_uuid_isolated

CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_rel_maal_urn_isolated ON aktivitet_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_rel_maal_uuid_isolated ON aktivitet_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_relation_idx_rel_maal_urn_isolated ON bruger_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS bruger_relation_idx_rel_maal_uuid_isolated ON bruger_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_del_relation_idx_rel_maal_urn_isolated ON dokument_del_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_del_relation_idx_rel_maal_uuid_isolated ON dokument_del_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_relation_idx_rel_maal_urn_isolated ON dokument_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS dokument_relation_idx_rel_maal_uuid_isolated ON dokument_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS facet_relation_idx_rel_maal_urn_isolated ON facet_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS facet_relation_idx_rel_maal_uuid_isolated ON facet_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_relation_idx_rel_maal_urn_isolated ON indsats_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS indsats_relation_idx_rel_maal_uuid_isolated ON indsats_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_rel_maal_urn_isolated ON interessefaellesskab_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_rel_maal_uuid_isolated ON interessefaellesskab_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_rel_maal_urn_isolated ON itsystem_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_rel_maal_uuid_isolated ON itsystem_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS klasse_relation_idx_rel_maal_urn_isolated ON klasse_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS klasse_relation_idx_rel_maal_uuid_isolated ON klasse_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_rel_maal_urn_isolated ON klassifikation_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_rel_maal_uuid_isolated ON klassifikation_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_rel_maal_urn_isolated ON loghaendelse_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_rel_maal_uuid_isolated ON loghaendelse_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_rel_maal_urn_isolated ON organisationenhed_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_rel_maal_uuid_isolated ON organisationenhed_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_rel_maal_urn_isolated ON organisationfunktion_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_rel_maal_uuid_isolated ON organisationfunktion_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisation_relation_idx_rel_maal_urn_isolated ON organisation_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS organisation_relation_idx_rel_maal_uuid_isolated ON organisation_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS sag_relation_idx_rel_maal_urn_isolated ON sag_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS sag_relation_idx_rel_maal_uuid_isolated ON sag_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_rel_maal_urn_isolated ON tilstand_relation (rel_maal_urn) WHERE rel_maal_urn IS NOT NULL;
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_rel_maal_uuid_isolated ON tilstand_relation (rel_maal_uuid) WHERE rel_maal_uuid IS NOT NULL;

-- virkning_aktoerref

CREATE INDEX IF NOT EXISTS aktivitet_attr_egenskaber_idx_virkning_aktoerref ON aktivitet_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_virkning_aktoerref ON aktivitet_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS aktivitet_tils_publiceret_idx_virkning_aktoerref ON aktivitet_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS aktivitet_tils_status_idx_virkning_aktoerref ON aktivitet_tils_status (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS bruger_attr_egenskaber_idx_virkning_aktoerref ON bruger_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS bruger_attr_udvidelser_idx_virkning_aktoerref ON bruger_attr_udvidelser (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS bruger_relation_idx_virkning_aktoerref ON bruger_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS bruger_tils_gyldighed_idx_virkning_aktoerref ON bruger_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_attr_egenskaber_idx_virkning_aktoerref ON dokument_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_del_egenskaber_idx_virkning_aktoerref ON dokument_del_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_del_relation_idx_virkning_aktoerref ON dokument_del_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_relation_idx_virkning_aktoerref ON dokument_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_tils_fremdrift_idx_virkning_aktoerref ON dokument_tils_fremdrift (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS dokument_variant_egenskaber_idx_virkning_aktoerref ON dokument_variant_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS facet_attr_egenskaber_idx_virkning_aktoerref ON facet_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS facet_relation_idx_virkning_aktoerref ON facet_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS facet_tils_publiceret_idx_virkning_aktoerref ON facet_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS indsats_attr_egenskaber_idx_virkning_aktoerref ON indsats_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS indsats_relation_idx_virkning_aktoerref ON indsats_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS indsats_tils_fremdrift_idx_virkning_aktoerref ON indsats_tils_fremdrift (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS indsats_tils_publiceret_idx_virkning_aktoerref ON indsats_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS interessefaellesskab_attr_egenskaber_idx_virkning_aktoerref ON interessefaellesskab_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_virkning_aktoerref ON interessefaellesskab_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS interessefaellesskab_tils_gyldighed_idx_virkning_aktoerref ON interessefaellesskab_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS itsystem_attr_egenskaber_idx_virkning_aktoerref ON itsystem_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_virkning_aktoerref ON itsystem_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS itsystem_tils_gyldighed_idx_virkning_aktoerref ON itsystem_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klasse_attr_egenskaber_idx_virkning_aktoerref ON klasse_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klasse_relation_idx_virkning_aktoerref ON klasse_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klasse_tils_publiceret_idx_virkning_aktoerref ON klasse_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klassifikation_attr_egenskaber_idx_virkning_aktoerref ON klassifikation_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_virkning_aktoerref ON klassifikation_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS klassifikation_tils_publiceret_idx_virkning_aktoerref ON klassifikation_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS loghaendelse_attr_egenskaber_idx_virkning_aktoerref ON loghaendelse_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_virkning_aktoerref ON loghaendelse_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS loghaendelse_tils_gyldighed_idx_virkning_aktoerref ON loghaendelse_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisation_attr_egenskaber_idx_virkning_aktoerref ON organisation_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationenhed_attr_egenskaber_idx_virkning_aktoerref ON organisationenhed_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_virkning_aktoerref ON organisationenhed_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationenhed_tils_gyldighed_idx_virkning_aktoerref ON organisationenhed_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_egenskaber_idx_virkning_aktoerref ON organisationfunktion_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_udvidelser_idx_virkning_aktoerref ON organisationfunktion_attr_udvidelser (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_virkning_aktoerref ON organisationfunktion_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisationfunktion_tils_gyldighed_idx_virkning_aktoerref ON organisationfunktion_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisation_relation_idx_virkning_aktoerref ON organisation_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS organisation_tils_gyldighed_idx_virkning_aktoerref ON organisation_tils_gyldighed (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS sag_attr_egenskaber_idx_virkning_aktoerref ON sag_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS sag_relation_idx_virkning_aktoerref ON sag_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS sag_tils_fremdrift_idx_virkning_aktoerref ON sag_tils_fremdrift (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS tilstand_attr_egenskaber_idx_virkning_aktoerref ON tilstand_attr_egenskaber (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_virkning_aktoerref ON tilstand_relation (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS tilstand_tils_publiceret_idx_virkning_aktoerref ON tilstand_tils_publiceret (((virkning).aktoerref));
CREATE INDEX IF NOT EXISTS tilstand_tils_status_idx_virkning_aktoerref ON tilstand_tils_status (((virkning).aktoerref));

-- virkning_aktoertypekode

CREATE INDEX IF NOT EXISTS aktivitet_attr_egenskaber_idx_virkning_aktoertypekode ON aktivitet_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_virkning_aktoertypekode ON aktivitet_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS aktivitet_tils_publiceret_idx_virkning_aktoertypekode ON aktivitet_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS aktivitet_tils_status_idx_virkning_aktoertypekode ON aktivitet_tils_status (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS bruger_attr_egenskaber_idx_virkning_aktoertypekode ON bruger_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS bruger_attr_udvidelser_idx_virkning_aktoertypekode ON bruger_attr_udvidelser (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS bruger_relation_idx_virkning_aktoertypekode ON bruger_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS bruger_tils_gyldighed_idx_virkning_aktoertypekode ON bruger_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_attr_egenskaber_idx_virkning_aktoertypekode ON dokument_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_del_egenskaber_idx_virkning_aktoertypekode ON dokument_del_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_del_relation_idx_virkning_aktoertypekode ON dokument_del_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_relation_idx_virkning_aktoertypekode ON dokument_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_tils_fremdrift_idx_virkning_aktoertypekode ON dokument_tils_fremdrift (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS dokument_variant_egenskaber_idx_virkning_aktoertypekode ON dokument_variant_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS facet_attr_egenskaber_idx_virkning_aktoertypekode ON facet_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS facet_relation_idx_virkning_aktoertypekode ON facet_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS facet_tils_publiceret_idx_virkning_aktoertypekode ON facet_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS indsats_attr_egenskaber_idx_virkning_aktoertypekode ON indsats_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS indsats_relation_idx_virkning_aktoertypekode ON indsats_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS indsats_tils_fremdrift_idx_virkning_aktoertypekode ON indsats_tils_fremdrift (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS indsats_tils_publiceret_idx_virkning_aktoertypekode ON indsats_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_virkning_aktoertypekode ON interessefaellesskab_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS interessefaellesskab_tils_gyldighed_idx_virkning_aktoertypekode ON interessefaellesskab_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS itsystem_attr_egenskaber_idx_virkning_aktoertypekode ON itsystem_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_virkning_aktoertypekode ON itsystem_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS itsystem_tils_gyldighed_idx_virkning_aktoertypekode ON itsystem_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klasse_attr_egenskaber_idx_virkning_aktoertypekode ON klasse_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klasse_relation_idx_virkning_aktoertypekode ON klasse_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klasse_tils_publiceret_idx_virkning_aktoertypekode ON klasse_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klassifikation_attr_egenskaber_idx_virkning_aktoertypekode ON klassifikation_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_virkning_aktoertypekode ON klassifikation_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS klassifikation_tils_publiceret_idx_virkning_aktoertypekode ON klassifikation_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS loghaendelse_attr_egenskaber_idx_virkning_aktoertypekode ON loghaendelse_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_virkning_aktoertypekode ON loghaendelse_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS loghaendelse_tils_gyldighed_idx_virkning_aktoertypekode ON loghaendelse_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisation_attr_egenskaber_idx_virkning_aktoertypekode ON organisation_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisationenhed_attr_egenskaber_idx_virkning_aktoertypekode ON organisationenhed_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_virkning_aktoertypekode ON organisationenhed_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisationenhed_tils_gyldighed_idx_virkning_aktoertypekode ON organisationenhed_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_virkning_aktoertypekode ON organisationfunktion_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisationfunktion_tils_gyldighed_idx_virkning_aktoertypekode ON organisationfunktion_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisation_relation_idx_virkning_aktoertypekode ON organisation_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS organisation_tils_gyldighed_idx_virkning_aktoertypekode ON organisation_tils_gyldighed (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS sag_attr_egenskaber_idx_virkning_aktoertypekode ON sag_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS sag_relation_idx_virkning_aktoertypekode ON sag_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS sag_tils_fremdrift_idx_virkning_aktoertypekode ON sag_tils_fremdrift (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS tilstand_attr_egenskaber_idx_virkning_aktoertypekode ON tilstand_attr_egenskaber (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_virkning_aktoertypekode ON tilstand_relation (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS tilstand_tils_publiceret_idx_virkning_aktoertypekode ON tilstand_tils_publiceret (((virkning).aktoertypekode));
CREATE INDEX IF NOT EXISTS tilstand_tils_status_idx_virkning_aktoertypekode ON tilstand_tils_status (((virkning).aktoertypekode));

-- virkning_notetekst

CREATE INDEX IF NOT EXISTS aktivitet_attr_egenskaber_idx_virkning_notetekst ON aktivitet_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_attr_egenskaber_pat_virkning_notetekst ON aktivitet_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_relation_idx_virkning_notetekst ON aktivitet_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_relation_pat_virkning_notetekst ON aktivitet_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_tils_publiceret_idx_virkning_notetekst ON aktivitet_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_tils_publiceret_pat_virkning_notetekst ON aktivitet_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_tils_status_idx_virkning_notetekst ON aktivitet_tils_status (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS aktivitet_tils_status_pat_virkning_notetekst ON aktivitet_tils_status (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_attr_egenskaber_idx_virkning_notetekst ON bruger_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_attr_egenskaber_pat_virkning_notetekst ON bruger_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_attr_udvidelser_idx_virkning_notetekst ON bruger_attr_udvidelser (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_attr_udvidelser_pat_virkning_notetekst ON bruger_attr_udvidelser (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_relation_idx_virkning_notetekst ON bruger_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_relation_pat_virkning_notetekst ON bruger_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_tils_gyldighed_idx_virkning_notetekst ON bruger_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS bruger_tils_gyldighed_pat_virkning_notetekst ON bruger_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_attr_egenskaber_idx_virkning_notetekst ON dokument_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_attr_egenskaber_pat_virkning_notetekst ON dokument_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_del_egenskaber_idx_virkning_notetekst ON dokument_del_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_del_egenskaber_pat_virkning_notetekst ON dokument_del_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_del_relation_idx_virkning_notetekst ON dokument_del_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_del_relation_pat_virkning_notetekst ON dokument_del_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_relation_idx_virkning_notetekst ON dokument_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_relation_pat_virkning_notetekst ON dokument_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_tils_fremdrift_idx_virkning_notetekst ON dokument_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_tils_fremdrift_pat_virkning_notetekst ON dokument_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_variant_egenskaber_idx_virkning_notetekst ON dokument_variant_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS dokument_variant_egenskaber_pat_virkning_notetekst ON dokument_variant_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_attr_egenskaber_idx_virkning_notetekst ON facet_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_attr_egenskaber_pat_virkning_notetekst ON facet_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_relation_idx_virkning_notetekst ON facet_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_relation_pat_virkning_notetekst ON facet_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_tils_publiceret_idx_virkning_notetekst ON facet_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS facet_tils_publiceret_pat_virkning_notetekst ON facet_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_attr_egenskaber_idx_virkning_notetekst ON indsats_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_attr_egenskaber_pat_virkning_notetekst ON indsats_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_relation_idx_virkning_notetekst ON indsats_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_relation_pat_virkning_notetekst ON indsats_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_tils_fremdrift_idx_virkning_notetekst ON indsats_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_tils_fremdrift_pat_virkning_notetekst ON indsats_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_tils_publiceret_idx_virkning_notetekst ON indsats_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS indsats_tils_publiceret_pat_virkning_notetekst ON indsats_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_attr_egenskaber_idx_virkning_notetekst ON interessefaellesskab_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_attr_egenskaber_pat_virkning_notetekst ON interessefaellesskab_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_idx_virkning_notetekst ON interessefaellesskab_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_relation_pat_virkning_notetekst ON interessefaellesskab_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_tils_gyldighed_idx_virkning_notetekst ON interessefaellesskab_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS interessefaellesskab_tils_gyldighed_pat_virkning_notetekst ON interessefaellesskab_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_attr_egenskaber_idx_virkning_notetekst ON itsystem_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_attr_egenskaber_pat_virkning_notetekst ON itsystem_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_relation_idx_virkning_notetekst ON itsystem_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_relation_pat_virkning_notetekst ON itsystem_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_tils_gyldighed_idx_virkning_notetekst ON itsystem_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS itsystem_tils_gyldighed_pat_virkning_notetekst ON itsystem_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_attr_egenskaber_idx_virkning_notetekst ON klasse_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_attr_egenskaber_pat_virkning_notetekst ON klasse_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_relation_idx_virkning_notetekst ON klasse_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_relation_pat_virkning_notetekst ON klasse_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_tils_publiceret_idx_virkning_notetekst ON klasse_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klasse_tils_publiceret_pat_virkning_notetekst ON klasse_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_attr_egenskaber_idx_virkning_notetekst ON klassifikation_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_attr_egenskaber_pat_virkning_notetekst ON klassifikation_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_relation_idx_virkning_notetekst ON klassifikation_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_relation_pat_virkning_notetekst ON klassifikation_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_tils_publiceret_idx_virkning_notetekst ON klassifikation_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS klassifikation_tils_publiceret_pat_virkning_notetekst ON klassifikation_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_attr_egenskaber_idx_virkning_notetekst ON loghaendelse_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_attr_egenskaber_pat_virkning_notetekst ON loghaendelse_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_relation_idx_virkning_notetekst ON loghaendelse_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_relation_pat_virkning_notetekst ON loghaendelse_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_tils_gyldighed_idx_virkning_notetekst ON loghaendelse_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS loghaendelse_tils_gyldighed_pat_virkning_notetekst ON loghaendelse_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_attr_egenskaber_idx_virkning_notetekst ON organisation_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_attr_egenskaber_pat_virkning_notetekst ON organisation_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_attr_egenskaber_idx_virkning_notetekst ON organisationenhed_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_attr_egenskaber_pat_virkning_notetekst ON organisationenhed_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_relation_idx_virkning_notetekst ON organisationenhed_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_relation_pat_virkning_notetekst ON organisationenhed_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_tils_gyldighed_idx_virkning_notetekst ON organisationenhed_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationenhed_tils_gyldighed_pat_virkning_notetekst ON organisationenhed_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_egenskaber_idx_virkning_notetekst ON organisationfunktion_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_egenskaber_pat_virkning_notetekst ON organisationfunktion_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_udvidelser_idx_virkning_notetekst ON organisationfunktion_attr_udvidelser (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_attr_udvidelser_pat_virkning_notetekst ON organisationfunktion_attr_udvidelser (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_idx_virkning_notetekst ON organisationfunktion_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_relation_pat_virkning_notetekst ON organisationfunktion_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_tils_gyldighed_idx_virkning_notetekst ON organisationfunktion_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisationfunktion_tils_gyldighed_pat_virkning_notetekst ON organisationfunktion_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_relation_idx_virkning_notetekst ON organisation_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_relation_pat_virkning_notetekst ON organisation_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_tils_gyldighed_idx_virkning_notetekst ON organisation_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS organisation_tils_gyldighed_pat_virkning_notetekst ON organisation_tils_gyldighed (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_attr_egenskaber_idx_virkning_notetekst ON sag_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_attr_egenskaber_pat_virkning_notetekst ON sag_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_relation_idx_virkning_notetekst ON sag_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_relation_pat_virkning_notetekst ON sag_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_tils_fremdrift_idx_virkning_notetekst ON sag_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS sag_tils_fremdrift_pat_virkning_notetekst ON sag_tils_fremdrift (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_attr_egenskaber_idx_virkning_notetekst ON tilstand_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_attr_egenskaber_pat_virkning_notetekst ON tilstand_attr_egenskaber (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_relation_idx_virkning_notetekst ON tilstand_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_relation_pat_virkning_notetekst ON tilstand_relation (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_tils_publiceret_idx_virkning_notetekst ON tilstand_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_tils_publiceret_pat_virkning_notetekst ON tilstand_tils_publiceret (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_tils_status_idx_virkning_notetekst ON tilstand_tils_status (((virkning).notetekst));
CREATE INDEX IF NOT EXISTS tilstand_tils_status_pat_virkning_notetekst ON tilstand_tils_status (((virkning).notetekst));
