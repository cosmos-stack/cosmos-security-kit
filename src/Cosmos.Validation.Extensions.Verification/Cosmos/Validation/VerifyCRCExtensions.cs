using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyCRCExtensions
    {
        public static IPredicateValueRuleBuilder VerifyCRC(this IValueRuleBuilder builder, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyCRC(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyCRC(this IValueRuleBuilder builder, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(CrcHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyCRC(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return builder.VerifyCRC(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyCRC(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(CrcHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyCRC<T>(this IValueRuleBuilder<T> builder, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyCRC<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyCRC<T>(this IValueRuleBuilder<T> builder, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(CrcHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyCRC<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return builder.VerifyCRC<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyCRC<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(CrcHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyCRC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, CrcTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyCRC<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyCRC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, CrcTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(CrcHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyCRC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, CrcTypes type)
        {
            return builder.VerifyCRC<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyCRC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, CrcTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(CrcHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

    }
}