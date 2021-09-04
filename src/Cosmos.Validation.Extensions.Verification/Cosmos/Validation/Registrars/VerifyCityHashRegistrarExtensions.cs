using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyCityHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyCityHash(this IValueFluentValidationRegistrar registrar, string hexVal, CityHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCityHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyCityHash(this IValueFluentValidationRegistrar registrar, string hexVal, CityHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CityHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyCityHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, CityHashTypes type)
        {
            return registrar.VerifyCityHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyCityHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, CityHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(CityHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyCityHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, CityHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCityHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyCityHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, CityHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CityHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyCityHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, CityHashTypes type)
        {
            return registrar.VerifyCityHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyCityHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, CityHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(CityHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCityHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, CityHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCityHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCityHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, CityHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CityHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCityHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, CityHashTypes type)
        {
            return registrar.VerifyCityHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCityHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, CityHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(CityHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}