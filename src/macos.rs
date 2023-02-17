use crate::Certificate;

use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use std::collections::HashMap;
use std::io::{Error, ErrorKind};

use sha2::{Digest, Sha256};

// Format an iterator of u8 into a hex string
pub(super) fn hex<'a>(input: impl IntoIterator<Item = &'a u8>) -> String {
    input
        .into_iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn load_native_certs() -> Result<Vec<Certificate>, Error> {
    // The various domains are designed to interact like this:
    //
    // "Per-user Trust Settings override locally administered
    //  Trust Settings, which in turn override the System Trust
    //  Settings."
    //
    // So we collect the certificates in this order; as a map of
    // their DER encoding to what we'll do with them.  We don't
    // overwrite existing elements, which mean User settings
    // trump Admin trump System, as desired.

    let mut all_certs = HashMap::new();

    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let ts = TrustSettings::new(*domain);
        let iter = ts
            .iter()
            .map_err(|err| Error::new(ErrorKind::Other, err))?;

        for cert in iter {
            let der = cert.to_der();

            // If there are no specific trust settings, the default
            // is to trust the certificate as a root cert.  Weird API but OK.
            // The docs say:
            //
            // "Note that an empty Trust Settings array means "always trust this cert,
            //  with a resulting kSecTrustSettingsResult of kSecTrustSettingsResultTrustRoot".
            let trusted = ts
                .tls_trust_settings_for_certificate(&cert)
                .map_err(|err| Error::new(ErrorKind::Other, err))?
                .unwrap_or(TrustSettingsForCertificate::TrustRoot);

            // The Apple root store includes some certificates that are distrusted dynamically.
            // These are listed at https://support.apple.com/en-us/HT212865.
            // The ideal fix would be to integrate rustls directly with the macOS platform verifier,
            // to automatically get updates to these dynamically distrusted certificates. However,
            // until that can happen we do a best effort job of blocking these. See
            // https://github.com/rustls/rustls-native-certs/issues/25.
            // These hashes were fetched from the above URL on 2023-02-17.
            let mut hasher = Sha256::new();
            hasher.update(der);
            match hex(&hasher.finalize()) {
                "e3268f6106ba8b665a1a962ddea1459d2a46972f1f2440329b390b895749ad45" => continue,
                "0ed3ffab6c149c8b4e71058e8668d429abfda681c2fff508207641f0d751a3e5" => continue,
                "f96f23f4c3e79c077a46988d5af5900676a0f039cb645dd17549b216c82440ce" => continue,
                "fcbfe2886206f72b27593c8b070297e12d769ed10ed7930705a8098effc14d17" => continue,
                "2a99f5bc1174b73cbb1d620884e01c34e51ccb3978da125f0e33268883bf4158" => continue,
                "152a402bfcdf2cd548054d2275b39c7fca3ec0978078b0f0ea76e561a6c7433e" => continue,
                "6cc05041e6445e74696c4cfbc9f80f543b7eabbb44b4ce6f787c6a9971c42f17" => continue,
                "e28393773da845a679f2080cc7fb44a3b7a1c3792cb7eb7729fdcb6a8d99aea7" => continue,
                "ae4457b40d9eda96677b0d3c92d57b5177abd7ac1037958356d1e094518be5f2" => continue,
                "507941c74460a0b47086220d4e9932572ab5d1b5bbcb8980ab1cb17651a844d2" => continue,
                "abd055c297005a89e4458ae34d4bc77e67db0fe1be575842c4efb7e8c3e05839" => continue,
                "37d51006c512eaab626421f1ec8c92013fc5f82ae98ee533eb4619b8deb4d06c" => continue,
                "b478b812250df878635c2aa7ec7d155eaa625ee82916e2cd294361886cd1fbd4" => continue,
                "70b922bfda0e3f4a342e4ee22d579ae598d071cc5ec9c30f123680340388aea5" => continue,
                "bc104f15a48be709dca542a7e1d4b9df6f054527e802eaa92d595444258afe71" => continue,
                "6fdb3f76c8b801a75338d8a50a7c02879f6198b57e594d318d3832900fedcd79" => continue,
                "56c77128d98c18d91b4cfdffbc25ee9103d4758ea2abad826a90f3457d460eb4" => continue,
                "27995829fe6a7515c1bfe848f9c4761db16c225929257bf40d0894f29ea8baf2" => continue,
                "b7c36231706e81078c367cb896198f1e3208dd926949dd8f5709a410f75b6292" => continue,
                "00309c736dd661da6f1eb24173aa849944c168a43a15bffd192eecfdb6f8dbd2" => continue,
                "a22dba681e97376e2d397d728aae3a9b6296b9fdba60bc2e11f647f2c675fb37" => continue,
                "91e5cc32910686c5cac25c18cc805696c7b33868c280caf0c72844a2a8eb91e2" => continue,
                "3c4fb0b95ab8b30032f432b86f535fe172c185d0fd39865837cf36187fa6f428" => continue,
                "c766a9bef2d4071c863a31aa4920e813b2d198608cb7b7cfe21143b836df09ea" => continue,
                "e17890ee09a3fbf4f48b9c414a17d637b7a50647e9bc752322727fcc1742a911" => continue,
                "c7ba6567de93a798ae1faa791e712d378fae1f93c4397fea441bb7cbe6fd5995" => continue,
                "21db20123660bb2ed418205da11ee7a85a65e2bc6e55b5af7e7899c8a266d92e" => continue,
                "f09b122c7114f4a09bd4ea4f4a99d558b46e4c25cd81140d29c05613914c3841" => continue,
                "d95fea3ca4eedce74cd76e75fc6d1ff62c441f0fa8bc77f034b19e5db258015d" => continue,
                "363f3c849eab03b0a2a0f636d7b86d04d3ac7fcfe26a0a9121ab9795f6e176df" => continue,
                "9d190b2e314566685be8a889e27aa8c7d7ae1d8aaddba3c1ecf9d24863cd34b9" => continue,
                "fe863d0822fe7a2353fa484d5924e875656d3dc9fb58771f6f616f9d571bc592" => continue,
                "cb627d18b58ad56dde331a30456bc65c601a4e9b18dedcea08e7daaa07815ff0" => continue,
                "53dfdfa4e297fcfe07594e8c62d5b8ab06b32c7549f38a163094fd6429d5da43" => continue,
                "b32396746453442f353e616292bb20bbaa5d23b546450fdb9c54b8386167d529" => continue,
                "8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f" => continue,
                "a4310d50af18a6447190372a86afaf8b951ffb431d837f1e5688b45971ed1557" => continue,
                "4b03f45807ad70f21bfc2cae71c9fde4604c064cf5ffb686bae5dbaad7fdd34c" => continue,
                "61dab17b03b2c239ae41d6a0712882d1484b821d0eb895d52f0fec634db713b8" => continue,
                "c1b48299aba5208fe9630ace55ca68a03eda5a519c8802a0d3a673be8f8e557d" => continue,
                "cbb5af185e942a2402f9eacbc0ed5bb876eea3c1223623d00447e4f3ba554b65" => continue,
                "92a9d9833fe1944db366e8bfae7a95b6480c2d6c6c2a1be65d4236b608fca1bb" => continue,
                "eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244" => continue,
                "69ddd7ea90bb57c93e135dc85ea6fcd5480b603239bdc454fc758b2a26cf7f79" => continue,
                "2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c" => continue,
                "4b15a4ee04f0bdb6c7ef1a15b63c72006688f7ca3d8ccdc0133b90a739e1aa55" => continue,
                "0c258a12a5674aef25f28ba7dcfaeceea348e541e6f5cc4ee63b71b361606ac3" => continue,
                "063e4afac491dfd332f3089b8542e94617d893d7fe944e10a7937ee29d9693c0" => continue,
                "8327bc8c9d69947b3de3c27511537267f59c21b9fa7b613fafbccd53b7024000" => continue,
                "ef3cb417fc8ebf6f97876c9e4ece39de1ea5fe649141d1028b7d11c0b2298ced" => continue,
                "136335439334a7698016a0d324de72284e079d7b5220bb8fbd747816eebebaca" => continue,
                "3b222e566711e992300dc0b15ab9473dafdef8c84d0cef7d3317b4c1821d1436" => continue,
                "92d8092ee77bc9208f0897dc05271894e63ef27933ae537fb983eef0eae3eec8" => continue,
            }

            all_certs.entry(der).or_insert(trusted);
        }
    }

    let mut certs = Vec::new();

    // Now we have all the certificates and an idea of whether
    // to use them.
    for (der, trusted) in all_certs.drain() {
        use TrustSettingsForCertificate::*;
        if let TrustRoot | TrustAsRoot = trusted {
            certs.push(Certificate(der));
        }
    }

    Ok(certs)
}
