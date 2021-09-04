using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyHMACRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyHMAC(this IValueFluentValidationRegistrar registrar, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyHMAC(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyHMAC(this IValueFluentValidationRegistrar registrar, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(HmacHandler.Verify()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyHMAC(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return registrar.VerifyHMAC(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyHMAC(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(HmacHandler.CustomVerify()(type)(key)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyHMAC<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyHMAC<T>(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyHMAC<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(HmacHandler.Verify()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyHMAC<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return registrar.VerifyHMAC<T>(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyHMAC<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(HmacHandler.CustomVerify()(type)(key)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyHMAC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyHMAC<T, TVal>(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyHMAC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(HmacHandler.Verify<TVal>()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyHMAC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return registrar.VerifyHMAC<T, TVal>(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyHMAC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(HmacHandler.CustomVerify<TVal>()(type)(key)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}