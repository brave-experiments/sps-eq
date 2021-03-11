#![warn(rust_2018_idioms, missing_docs)]
//! This crate implements Structure Preserving Signatures over Equivalence Classes (SPS-EQ) as
//! presented in the paper ["Structure-Preserving Signatures on Equivalence Classes and Constant-Size
//! Anonymous Credentials"][sps-eq] by Georg Fuchsbauer, Christian Hanser, and Daniel Slamanig.
//!
//! Table of Contents
//! =================
//! These notes explain how the SPS-EQ scheme works:
//!
//! * [SPS-EQ](#sps-eq)
//!
//! Notation
//! ========
//! We introduce the notation used throughout the documentation
//!
//! Let $\lambda$ be a security parameter.
//! We write $a\in_R A$ to denote that $a$ is chosen uniformly at random from the set $A$.
//! Let $\mathbb{G}_1,\mathbb{G}_2$ and $\mathbb{G}_T$ be cyclic groups of prime order $p$. Let
//! $g_1$ and $g_2$ be generators of $\mathbb{G}_1$ and $\mathbb{G}_2$, respectively. We call
//! $e:\mathbb{G}_1\times\mathbb{G}_2\rightarrow\mathbb{G}_T$ a bilinear map or pairing if it is
//! efficiently computable and the following holds:
//!
//! * Bilinearity: $e(g_1^a, g_2^b) = e(g_1, g_2)^{ab} = e(g_1^b, g_2^a)\forall a,b\in\mathbb{Z}_p$.
//! * Non-degeneracy: $e(g_1,g_2)\neq 1_{\mathbb{G}_T}$, i.e., $e(g_1,g_2)$ generates $\mathbb{G}_T$.
//!
//! <a name="sps-eq"></a>SPS-EQ
//! ====================
//! The SPS-EQ scheme is defined by 5 algorithms:
//! * $\texttt{BGGen}(1^\lambda):$ On input a security parameter $1^\lambda$, output a
//! bilinear-group description $\texttt{BG}\leftarrow\texttt{BGGen}(1^\lambda).$
//! * $\texttt{KeyGen}(\texttt{BG}):$ On input a bilinear-group description and a vector length $l$,
//! choose $\lbrace x_i\rbrace_{i\in\left[l\right]}{\in_R}{(\mathbb Z_p^*)^l}$, set secret key
//! $sk = \lbrace x_i\rbrace_{i\in\left[l\right]}$, compute public key
//! $pk\leftarrow\lbrace X_i\rbrace_{i\in\left[l\right]}=\lbrace g_2^{x_i}\rbrace_{i\in\left[2\right]}$
//! and output $(sk, pk)$.
//! * $\texttt{SignSps}(M, sk):$ On input a representative
//! $M = \lbrace M_i\rbrace_{i\in\left[l\right]}\in(\mathbb{G}_1^*)^l$ (todo: change 1)
//! of equivalence class $\left[M\right]$, and a secret key
//! $sk= \lbrace x_i\rbrace_{i\in\left[l\right]}$, choose
//! $y\in_R\mathbb Z_p^*$ and output $\sigma\leftarrow(Z, Y_1, Y_2)$ with
//!
//! \begin{equation}
//!     Z\leftarrow y\sum_{i\in\left[l\right]}M_i^{x_i} \hspace{2cm}
//!     Y_1\leftarrow g_1^{\frac{1}{y}} \hspace{2cm}
//!     Y_2\leftarrow g_2^{\frac{1}{y}}.
//! \end{equation}
//! * $\texttt{VerifySps}(M, \sigma, pk):$ On input a representative
//! $M = \lbrace M_i\rbrace_{i\in\left[l\right]}\in(\mathbb{G}_1)^l$ of equivalence class
//! $\left[M\right]$, a signature
//! $\sigma=(Z, Y_1, Y_2)\in\mathbb{G}_1\times\mathbb{G}_1^*\times\mathbb{G}_2^*$, and a public key
//! $pk=(X_i)_{i\in\left[l\right]}\in(\mathbb{G}_2^*)^l$, check whether
//!
//! \begin{equation}
//!     \prod_{i\in\left[l\right]}e(M_i, X_i) = e(Z, Y_2) \hspace{1cm}
//!     \wedge \hspace{1cm} e(Y_1, \mathbb{G}_2) = e(\mathbb{G}_1, Y_2).
//! \end{equation}
//! If this holds, output 1 and 0 otherwise.
//! * $\texttt{ChangeRepr(M, \sigma, f, pk)$: On input a representative
//! $M = \lbrace M_i\rbrace_{i\in\left[l\right]}\in(\mathbb{G}_1)^l$ of equivalence class
//! $\left[M\right]$, a signature
//! $\signature=(Z, Y_1, Y_2))\in\mathbb{G}_1\times\mathbb{G}_1^*\times\mathbb{G}_2^*$, the
//! randomness $f\in\mathbb Z_p^*$ and a public key $pk$, return $\bot$ if
//! $\texttt{VerifySps}(M, \sigma, pk) = 0$. Otherwise pick $\psi\in_R\mathbb Z_p^*$ and return
//! $(M^f, \sigma')$ with $\sigma'\leftarrow(\psi f Z, Y_1^{\frac{1}{\psi}}, Y_2^{\frac{1}{\psi}})$.
//!
//! \end{description}
//!
//! [sps-eq]: https://eprint.iacr.org/2014/944.pdf

mod errors;
#[allow(non_snake_case)]
pub mod sign;
pub mod verify;
