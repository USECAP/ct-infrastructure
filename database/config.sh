#!/bin/bash
set -e

set_listen_addresses() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(listen_addresses\s*=\s*)\S+/\1'$sedEscapedValue'/" "$PGDATA/postgresql.conf"
}

if [ "$1" = 'postgres' ]; then
	mkdir -p "$PGDATA"
	chown -R postgres "$PGDATA"

	chmod g+s /run/postgresql
	chown -R postgres /run/postgresql

	# look specifically for PG_VERSION, as it is expected in the DB dir
	if [ ! -s "$PGDATA/PG_VERSION" ]; then
		gosu postgres initdb

		# check password first so we can output the warning before postgres
		# messes it up
		if [ "$POSTGRES_PASSWORD" ]; then
			pass="PASSWORD '$POSTGRES_PASSWORD'"
			authMethod=md5
		else
			# The - option suppresses leading tabs but *not* spaces. :)
			cat >&2 <<-'EOWARN'
				****************************************************
				WARNING: No password has been set for the database.
				         This will allow anyone with access to the
				         Postgres port to access your database. In
				         Docker's default configuration, this is
				         effectively any other container on the same
				         system.

				         Use "-e POSTGRES_PASSWORD=password" to set
				         it in "docker run".
				****************************************************
			EOWARN

			pass=
			authMethod=trust
		fi

		{ echo; echo "host all all 0.0.0.0/0 $authMethod"; } >> "$PGDATA/pg_hba.conf"

		# internal start of server in order to allow set-up using psql-client
		# does not listen on TCP/IP and waits until start finishes
		gosu postgres pg_ctl -D "$PGDATA" \
			-o "-c listen_addresses=''" \
			-w start

		: ${POSTGRES_USER:=postgres}
		: ${POSTGRES_DB:=$POSTGRES_USER}
		export POSTGRES_USER POSTGRES_DB

        if psql -lqt | cut -d \| -f 1 | grep -w certwatch; then
            echo "hallo1sss"
        else
            psql --username postgres <<-EOSQL
				CREATE DATABASE certwatch ;
                CREATE USER crtsh WITH SUPERUSER $pass
			EOSQL

            psql --username postgres -d certwatch <<-EOSQL
              CREATE OR REPLACE FUNCTION x509_issuerName(bytea,integer DEFAULT NULL) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_keyAlgorithm(bytea) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_keySize(bytea) RETURNS integer
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_notAfter(bytea) RETURNS timestamp
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_notBefore(bytea) RETURNS timestamp
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_publicKeyMD5(bytea) RETURNS bytea
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_publicKey(bytea) RETURNS bytea
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_serialNumber(bytea) RETURNS bytea
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_signatureHashAlgorithm(bytea) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_signatureKeyAlgorithm(bytea) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_subjectName(bytea,integer DEFAULT NULL) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_commonName(bytea) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_extKeyUsages(bytea) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_isEKUPermitted(bytea,text) RETURNS boolean
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_certPolicies(bytea) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_isPolicyPermitted(bytea,text) RETURNS boolean
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_canIssueCerts(bytea) RETURNS boolean
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_getPathLenConstraint(bytea) RETURNS integer
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_nameAttributes(bytea,text,boolean) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_altNames(bytea,integer DEFAULT NULL,boolean DEFAULT TRUE) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_cRLDistributionPoints(bytea) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_authorityInfoAccess(bytea,integer DEFAULT NULL) RETURNS SETOF text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_print(bytea,integer DEFAULT NULL,integer DEFAULT NULL) RETURNS text
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION x509_verify(bytea,bytea) RETURNS boolean
        				AS '/libx509pq.so' LANGUAGE c IMMUTABLE;

        			CREATE OR REPLACE FUNCTION urlEncode(text) RETURNS text
        				AS '/libx509pq.so' LANGUAGE C IMMUTABLE STRICT;

        			CREATE OR REPLACE FUNCTION urlDecode(text) RETURNS text
        				AS '/libx509pq.so' LANGUAGE C IMMUTABLE STRICT;

        			CREATE OR REPLACE FUNCTION x509pq_opensslVersion() RETURNS text
        				AS '/libx509pq.so' LANGUAGE C IMMUTABLE;

        				CREATE EXTENSION pgcrypto;
		EOSQL

        		psql -U crtsh -d certwatch <<-EOSQL
        			CREATE TABLE ca (
        				ID						serial,
        				NAME					text		NOT NULL,
        				PUBLIC_KEY		bytea		NOT NULL,
        				BRAND					text,
        				CONSTRAINT ca_pk
        					PRIMARY KEY (ID)
        				);

        				CREATE UNIQUE INDEX ca_uniq
        				ON ca (NAME text_pattern_ops, PUBLIC_KEY);

        				CREATE INDEX ca_name
        				ON ca (lower(NAME) text_pattern_ops);

        				CREATE INDEX ca_brand
        				ON ca (lower(BRAND) text_pattern_ops);

        				CREATE INDEX ca_name_reverse
        				ON ca (reverse(lower(NAME)) text_pattern_ops);

        				CREATE INDEX ca_brand_reverse
        				ON ca (reverse(lower(BRAND)) text_pattern_ops);


        				CREATE TABLE certificate (
        				ID						serial,
        				CERTIFICATE				bytea		NOT NULL,
        				ISSUER_CA_ID			integer		NOT NULL,
        				EXPIRED                 boolean,
        				CONSTRAINT c_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT c_ica_fk
        					FOREIGN KEY (ISSUER_CA_ID)
        					REFERENCES ca(ID)
        				);

        				CREATE INDEX c_ica_typecanissue
        				ON certificate (ISSUER_CA_ID, x509_canIssueCerts(CERTIFICATE));

        				CREATE INDEX c_notafter_ica
        				ON certificate (x509_notAfter(CERTIFICATE), ISSUER_CA_ID);

        				CREATE INDEX c_serial_ica
        				ON certificate (x509_serialNumber(CERTIFICATE), ISSUER_CA_ID);

        				CREATE INDEX c_sha1
        				ON certificate (digest(CERTIFICATE, 'sha1'));

        				CREATE UNIQUE INDEX c_sha256
        				ON certificate (digest(CERTIFICATE, 'sha256'));

        				CREATE INDEX c_spki_sha1
        				ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha1'));

        				CREATE INDEX c_common_name
        				ON certificate (x509_commonName(CERTIFICATE));

        				CREATE TABLE invalid_certificate (
        				ID 										serial,
        				CERTIFICATE_ID				integer,
        				PROBLEMS							text,
        				CERTIFICATE_AS_LOGGED	bytea,
        				CONSTRAINT ic_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT ic_c_fk
        					FOREIGN KEY (CERTIFICATE_ID)
        					REFERENCES certificate(ID)
        				);

        				CREATE TYPE name_type AS ENUM (
        				'commonName', 'organizationName', 'emailAddress',
        				'rfc822Name', 'dNSName', 'iPAddress', 'organizationalUnitName'
        				);

        				CREATE TABLE certificate_identity (
        				ID								serial,
        				CERTIFICATE_ID		integer		NOT NULL,
        				NAME_TYPE					name_type	NOT NULL,
        				NAME_VALUE				text		NOT NULL,
        				ISSUER_CA_ID			integer,
        				CONSTRAINT ci_c_fk
        					FOREIGN KEY (CERTIFICATE_ID)
        					REFERENCES certificate(ID),
        				CONSTRAINT ci_ca_fk
        					FOREIGN KEY (ISSUER_CA_ID)
        					REFERENCES ca(ID)
        				);

        				CREATE UNIQUE INDEX ci_uniq
        				ON certificate_identity (CERTIFICATE_ID, lower(NAME_VALUE) text_pattern_ops, NAME_TYPE);

        				CREATE INDEX ci_forward
        				ON certificate_identity (lower(NAME_VALUE) text_pattern_ops, ISSUER_CA_ID, NAME_TYPE);

        				CREATE INDEX ci_reverse
        				ON certificate_identity (reverse(lower(NAME_VALUE)) text_pattern_ops, ISSUER_CA_ID, NAME_TYPE);

        				CREATE INDEX ci_ca
        				ON certificate_identity (ISSUER_CA_ID, lower(NAME_VALUE) text_pattern_ops, NAME_TYPE);

        				CREATE INDEX ci_dnsname
        				ON certificate_identity (reverse(lower(NAME_VALUE)) text_pattern_ops) WHERE NAME_TYPE='dNSName';

        				CREATE TABLE revoked_certificate (
        				ID 										serial,
        				CERTIFICATE_ID				integer,
        				DATE							timestamp,
        				REASON	text,
        				CONSTRAINT rc_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT rc_c_fk
        					FOREIGN KEY (CERTIFICATE_ID)
        					REFERENCES certificate(ID)
        				);

        				CREATE TABLE ca_certificate (
        				ID							serial,
        				CERTIFICATE_ID	integer,
        				CA_ID						integer,
        				CONSTRAINT cac_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT cac_c_fk
        					FOREIGN KEY (CERTIFICATE_ID)
        					REFERENCES certificate(ID),
        				CONSTRAINT cac_ca_fk
        					FOREIGN KEY (CA_ID)
        					REFERENCES ca(ID)
        				);

        				CREATE INDEX cac_ca_cert
        				ON ca_certificate (CA_ID, CERTIFICATE_ID);


        				CREATE TABLE ct_log (
        				ID										serial,
        				URL										text,
        				NAME									text,
        				PUBLIC_KEY						bytea,
        				LATEST_ENTRY_ID				integer,
        				LATEST_UPDATE					timestamp,
        				OPERATOR							text,
        				INCLUDED_IN_CHROME		integer,
        				IS_ACTIVE							boolean,
        				LATEST_STH_TIMESTAMP	timestamp,
        				MMD_IN_SECONDS				integer,
        				CHROME_ISSUE_NUMBER		integer,
        				CONSTRAINT ctl_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT crl_url_unq
        					UNIQUE (URL)
        				);

        				CREATE UNIQUE INDEX ctl_sha256_pubkey
        				ON ct_log (digest(PUBLIC_KEY, 'sha256'));

        				CREATE TABLE ct_log_entry (
        				ID							serial,
        				CERTIFICATE_ID	integer,
        				CT_LOG_ID				smallint,
        				ENTRY_ID				integer,
        				ENTRY_TIMESTAMP	timestamp,
        				CONSTRAINT ctle_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT ctle_c_fk
        					FOREIGN KEY (CERTIFICATE_ID)
        					REFERENCES certificate(ID),
        				CONSTRAINT ctle_ctl_fk
        					FOREIGN KEY (CT_LOG_ID)
        					REFERENCES ct_log(ID)
        				);

        				CREATE INDEX ctle_le
        				ON ct_log_entry (CT_LOG_ID, ENTRY_ID);

        				CREATE INDEX ctle_el
        				ON ct_log_entry (ENTRY_ID, CT_LOG_ID);

        				CREATE TABLE metadata (
        				ID		serial,
        				NAME_TYPE	text,
        				NAME_VALUE	integer,
        				CONSTRAINT metadata_pk
        					PRIMARY KEY (ID),
        				CONSTRAINT metadata_nt_unq
        					UNIQUE (NAME_TYPE)
        				);

        				INSERT INTO metadata(NAME_TYPE, NAME_VALUE) VALUES
        					('number_of_certs',0),
        					('number_of_cas',0),
        					('number_of_active_certs',0),
        					('number_of_expired_certs',0),
        					('number_of_revoked_certs',0),
        					('number_of_misissued_certs',0),
        					('number_of_correctly_behaving_cas',0),
        					('number_of_interesting_cas',0),
        					('number_of_certs_in_biggest_log',0),
        					('number_of_certs_in_smallest_log',0);
        					
                                        CREATE TABLE issues (
                                            ID         serial,
                                            NAME       text NOT NULL,
                                            TITLE text NOT NULL,
                                            DESCRIPTION text NOT NULL,
                                            CONSTRAINT i_pk
                                                PRIMARY KEY (ID),
                                            CONSTRAINT issue_unq UNIQUE (NAME)
                                        );
                                        
                                        CREATE TABLE found_issues (
                                            ID  serial,
                                            CERTIFICATE integer NOT NULL,
                                            ISSUE       integer NOT NULL,
                                            EXTRA	text,
                                            TIMESTAMP   timestamp DEFAULT current_timestamp,
                                            CONSTRAINT fi_pk
                                                PRIMARY KEY (ID),
                                            CONSTRAINT fi_c_fk
                                                FOREIGN KEY (CERTIFICATE)
                                                REFERENCES CERTIFICATE(ID),
                                            CONSTRAINT fi_i_fk
                                                FOREIGN KEY (ISSUE)
                                                REFERENCES ISSUES(ID),
                                            CONSTRAINT fi_unq
                                                UNIQUE (CERTIFICATE, ISSUE)
                                        );
                                        
                                        
                                        INSERT INTO issues(NAME, TITLE, DESCRIPTION) VALUES
                                            ('ctobs.issues.first_cert_dnsname', 'First certificate (dnsname)','This is the first certificate for this dnsname that we know of.'),
                                            ('ctobs.issues.first_cert_cn', 'First certificate (common name)','This is the first certificate for this common name that we know of.'),
                                            ('ctobs.issues.ca_switch', 'CA switch','This certificate has been issued by another CA than the previous one(s).'),
                                            ('ctobs.issues.early_renewal', 'Early renewal','This certificate has been renewed long before the previous certificate expired.'),
                                            ('ctobs.issues.weaker_crypto_keysize', 'Weaker crypto (keysize)','This certificate uses the same algorithm with a shorter key size than the previous certificate(s).'),
                                            ('ctobs.issues.weaker_crypto_algorithm', 'Weaker crypto (algorithm)','This certificate uses a weaker algorithm than the previous certificate(s).'),
                                            ('ctobs.issues.rfc_violation', 'RFC violation','This certificate does not conform to the RFC.');
                                        

                        CREATE TABLE certificate_analysis (
                            ID serial,
                            type text,
                            value integer
                        );

                        INSERT INTO certificate_analysis (type, value) VALUES ('es_last_cert_id',-1);

                        CREATE TABLE notification_dns_names (
                            ID serial,
                            name text,
                            CONSTRAINT notification_unq
        					    UNIQUE (id)
        				);

                        CREATE TABLE notification_email (
                            ID serial,
                            NOTIFY_FOR integer,
                            EMAIL text,
                            VALIDATE_KEY text,
                            VALIDATED boolean,
                            ACTIVE boolean,
                            notification_dns_names_id integer,
                            CONSTRAINT not_dns_fk
        					    FOREIGN KEY (notification_dns_names_id)
        					    REFERENCES notification_dns_names(ID)
                        );

        				GRANT SELECT ON ca TO crtsh;

        				GRANT SELECT ON certificate TO crtsh;

        				GRANT SELECT ON certificate_identity TO crtsh;

        				GRANT SELECT ON ca_certificate TO crtsh;

        				GRANT SELECT ON ct_log TO crtsh;

                                        GRANT SELECT ON ct_log_entry TO crtsh;

        				GRANT SELECT ON metadata TO crtsh;

                                        GRANT SELECT ON issues TO crtsh;
                                        
        				GRANT SELECT ON found_issues TO crtsh;

        				\i /certwatch_db/download_cert.fnc
        				\i /certwatch_db/extract_cert_names.fnc
        				\i /certwatch_db/get_parameter.fnc
        				\i /certwatch_db/html_escape.fnc
        				\i /certwatch_db/import_cert.fnc
        				\i /certwatch_db/import_ct_cert.fnc
        				\i /certwatch_db/web_apis.fnc

                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.googleapis.com/pilot','Google Pilot log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==','Google',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.googleapis.com/aviator','Google Aviator log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==','Google',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.googleapis.com/rocketeer','Google Rocketeer log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==','Google',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct1.digicert-ct.com/log','DigiCert Log Server','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==','DigiCert',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.izenpe.com','Izenpe log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==','Izenpe',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://log.certly.io','Certly.IO log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==','Certly',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.ws.symantec.com','Symantec log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==','Symantec',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://vega.ws.symantec.com','Symantec VEGA log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==','Symantec',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ctlog.api.venafi.com','Venafi log','MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB','Venafi',86400,true);
                        INSERT INTO ct_log (url, name, public_key, operator, mmd_in_seconds, is_active) VALUES
                            ('https://ct.wosign.com','WoSign log','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1+wvK3VPN7yjQ7qLZWY8fWrlDCqmwuUm/gx9TnzwOrzi0yLcAdAfbkOcXG6DrZwV9sSNYLUdu6NiaX7rp6oBmw==','WoSign',86400,true);

		EOSQL
        		echo
        fi

		if [ "$POSTGRES_USER" = 'postgres' ]; then
			op='ALTER'
		else
			op='CREATE'
		fi

		psql --username postgres <<-EOSQL
			$op USER "$POSTGRES_USER" WITH SUPERUSER $pass ;
		EOSQL


		echo
		for f in /docker-entrypoint-initdb.d/*; do
			case "$f" in
				*.sh)  echo "$0: running $f"; . "$f" ;;
				*.sql) echo "$0: running $f"; psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" < "$f" && echo ;;
				*)     echo "$0: ignoring $f" ;;
			esac
			echo
		done

		gosu postgres pg_ctl -D "$PGDATA" -m fast -w stop
		set_listen_addresses '*'

		echo
		echo 'PostgreSQL init process complete; ready for start up.'
		echo
	fi

	exec gosu postgres "$@"
fi

exec "$@"
