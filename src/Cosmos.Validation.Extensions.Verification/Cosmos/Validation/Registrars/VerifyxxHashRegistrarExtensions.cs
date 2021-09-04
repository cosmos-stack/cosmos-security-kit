using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyXXHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(xxHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return registrar.VerifyMessageDigest(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(xxHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(xxHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return registrar.VerifyMessageDigest<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(xxHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(xxHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return registrar.VerifyMessageDigest<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(xxHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}