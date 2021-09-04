using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyCRCRegistrarExtensions
    {
        public static IPredicateValidationRegistrar VerifyCRC(this IValueFluentValidationRegistrar registrar, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCRC(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyCRC(this IValueFluentValidationRegistrar registrar, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CrcHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyCRC(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return registrar.VerifyCRC(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyCRC(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return registrar.Func(CrcHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValidationRegistrar<T> VerifyCRC<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCRC<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyCRC<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CrcHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyCRC<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return registrar.VerifyCRC<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyCRC<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return registrar.Func(CrcHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        
        public static IPredicateValidationRegistrar<T, TVal> VerifyCRC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyCRC<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCRC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(CrcHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCRC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return registrar.VerifyCRC<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyCRC<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return registrar.Func(CrcHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

    }
}