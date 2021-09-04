using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifySpookyHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifySpookyHash(this IValueFluentValidationRegistrar registrar, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySpookyHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySpookyHash(this IValueFluentValidationRegistrar registrar, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(SpookyHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifySpookyHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return registrar.VerifySpookyHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySpookyHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(SpookyHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifySpookyHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySpookyHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySpookyHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(SpookyHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifySpookyHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return registrar.VerifySpookyHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySpookyHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(SpookyHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySpookyHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySpookyHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySpookyHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(SpookyHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySpookyHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return registrar.VerifySpookyHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySpookyHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(SpookyHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}