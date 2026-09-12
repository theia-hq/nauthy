//! A `sheer:` capability link: the shareable wire form of a [`Cap`], parsed and verified at construction.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;

use crate::VerifyKey;
use crate::cap::{Cap, CapError, Identity, Request};
#[cfg(feature = "tokio-fs")]
use crate::revocations::{DenylistError, FileDenylist};
use crate::service::Service;

/// A `sheer:` capability link: the shareable text form of a [`Cap`], validated at construction.
///
/// [`FromStr`] runs [`Cap::parse`], the same check the far gate runs, so holding a `Link` proves the bytes
/// decoded and the signature chain verified against the embedded root; [`Display`](fmt::Display) renders the
/// exact text to present. It is the typed owner of the raw form: [`Cap::link`] produces one and no public
/// signature traffics in the raw string. The parsed cap is carried beside the text, so the link's root
/// (the node it addresses) is a plain read rather than a second parse.
#[derive(Clone)]
pub struct Link {
    cap: Cap,
    text: String,
}

impl Link {
    /// Mint a `sheer:` link granting `service`, valid for `lifetime` from now.
    ///
    /// Left attenuable: any holder may narrow it with [`narrow`](Self::narrow) and hand the narrower result
    /// on, and can never broaden it (the crypto enforces monotonicity). Call [`seal`](Self::seal) to mint a
    /// non-delegable link instead. Offline: needs the signing `identity` but no network.
    pub fn mint(
        identity: &Identity,
        service: &Service,
        lifetime: Duration,
    ) -> Result<Self, CapError> {
        Self::of(identity.mint(service, Request::expires_in(lifetime))?)
    }

    /// Mint a device-bound `sheer:` link granting `service` to the proven device `bound_to`, valid for
    /// `lifetime` from now.
    ///
    /// The standing per-service grant for one device ([`Identity::mint_bound`]): the link is inert unless
    /// presented by `bound_to`, so a copy observed in flight or at rest grants no one. Always sealed: a
    /// bound link is non-delegable by construction (it cannot be narrowed and handed onward, which is the
    /// point of binding it). Offline: needs the signing `identity` but no network.
    pub fn mint_bound(
        identity: &Identity,
        service: &Service,
        bound_to: VerifyKey,
        lifetime: Duration,
    ) -> Result<Self, CapError> {
        Self::of(
            identity
                .mint_bound(service, bound_to, Request::expires_in(lifetime))?
                .seal()?,
        )
    }

    /// Mint a signet-bound `sheer:` link granting `service` to any device of the fleet `foreign_root`,
    /// valid for `lifetime` from now.
    ///
    /// The work-sim primitive ([`Identity::mint_authority_slip`]): issue ONCE to a person's signet
    /// `foreign_root`, and every device that signet vouches for may use it. Inert alone: the far gate admits
    /// it only when the presenter ALSO proves membership under `foreign_root`. Always sealed:
    /// theft-resistant and non-delegable by construction (like [`mint_bound`](Self::mint_bound)). Offline:
    /// needs the signing `identity` but no network.
    pub fn mint_signet(
        identity: &Identity,
        service: &Service,
        foreign_root: VerifyKey,
        lifetime: Duration,
    ) -> Result<Self, CapError> {
        Self::of(
            identity
                .mint_authority_slip(service, foreign_root, Request::expires_in(lifetime))?
                .seal()?,
        )
    }

    /// Seal this link so no holder can attenuate it: it still verifies, and cannot be narrowed or re-shared.
    ///
    /// The honest non-delegable grant ([`Cap::seal`]); a sealed link rejects [`narrow`](Self::narrow) with
    /// [`CapError::Attenuate`].
    pub fn seal(&self) -> Result<Self, CapError> {
        Self::of(self.cap.seal()?)
    }

    /// Narrow this link offline: tighten its service and/or shorten its expiry, returning the tighter link.
    ///
    /// Only ever adds checks, so the result is never broader than the input. At least one of `service` or
    /// `shorten` must be given, else [`CapError::EmptyAttenuation`]; a sealed link is refused with
    /// [`CapError::Attenuate`].
    pub fn narrow(
        &self,
        service: Option<&Service>,
        shorten: Option<Duration>,
    ) -> Result<Self, CapError> {
        let shorten = shorten.map(Request::expires_in);
        Self::of(self.cap.attenuate(service, shorten)?)
    }

    /// Revoke this link into an open denylist, so the gate refuses it and everything attenuated from it.
    ///
    /// The caller opens the denylist (from wherever it persists revocations) and passes it BY REF; this
    /// never reads a path. It records EXACTLY the link's id and every narrower cap delegated from it, NOT
    /// the wider grant it was attenuated from.
    #[cfg(feature = "tokio-fs")]
    pub async fn revoke(&self, denylist: &mut FileDenylist) -> Result<(), DenylistError> {
        denylist.revoke(&self.cap).await
    }

    /// The root identity this link addresses: the key to dial and the issuer that must verify it.
    pub fn root(&self) -> VerifyKey {
        self.cap.root()
    }

    /// The exact `sheer:` text, as parsed or minted: what [`Display`](fmt::Display) renders and a caller
    /// presents on the wire.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Wrap an already-parsed cap with its encoded text. The one raw-form encoder: [`Cap::link`] and every
    /// minting operation funnel through here, so the text and the cap can never drift apart.
    pub(crate) fn of(cap: Cap) -> Result<Self, CapError> {
        let text = cap.link_text()?;
        Ok(Self { cap, text })
    }
}

impl FromStr for Link {
    type Err = CapError;

    /// Parse-don't-validate at the wire edge: rejects a bad scheme, a malformed root key, bad base32, or a
    /// token whose signature chain does not check against the embedded root. It does NOT evaluate the
    /// caveats (service, expiry); that is the gate's job at connect time. The parsed text is kept verbatim,
    /// so a present-through link carries the exact bytes the holder pasted.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            cap: Cap::parse(text)?,
            text: text.to_owned(),
        })
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Link {
    /// Print the link text: a `sheer:` link is public share material, not a secret, and its whole identity
    /// is the bytes a holder pastes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Link").field(&self.text).finish()
    }
}
