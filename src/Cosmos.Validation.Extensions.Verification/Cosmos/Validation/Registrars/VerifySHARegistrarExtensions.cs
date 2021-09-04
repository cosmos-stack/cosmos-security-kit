using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifySHARegistrarExtensions
    {
        #region Common Entry

        public static IPredicateValidationRegistrar VerifySHA(this IValueFluentValidationRegistrar registrar, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA(this IValueFluentValidationRegistrar registrar, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifySHA(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return registrar.VerifySHA(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return registrar.VerifySHA<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return registrar.VerifySHA<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifySHA1

        public static IPredicateValidationRegistrar VerifySHA1(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA1(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA1(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValidationRegistrar VerifySHA1(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA1(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA1(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA1<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA1(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA1<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA1<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA1(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA1<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA1<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA1<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        #endregion

        #region VerifySHA2/224

        public static IPredicateValidationRegistrar VerifySHA224(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA224(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA224(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValidationRegistrar VerifySHA224(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA224(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA224(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA224<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA224(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA224<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA224<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA224(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA224<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA224<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA224<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA224<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA224<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA224<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA224<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        #endregion

        #region VerifySHA2/256

        public static IPredicateValidationRegistrar VerifySHA256(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA256(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA256(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValidationRegistrar VerifySHA256(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA256(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA256(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA256<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA256(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA256<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA256<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA256(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA256<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA256<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA256<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA256<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA256<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA256<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA256<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        #endregion

        #region VerifySHA2/384

        public static IPredicateValidationRegistrar VerifySHA384(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA384(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA384(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValidationRegistrar VerifySHA384(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA384(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA384(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA384<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA384<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA384<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA384<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA384<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA384<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA384<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA384<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA384<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA384<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA384<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA384<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        #endregion

        #region VerifySHA2/512

        public static IPredicateValidationRegistrar VerifySHA512(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA512(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySHA512(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValidationRegistrar VerifySHA512(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA512(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySHA512(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA512<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA512(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA512<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValidationRegistrar<T> VerifySHA512<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA512(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySHA512<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA512<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySHA512<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA512<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA512<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySHA512<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySHA512<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        #endregion
    }
}