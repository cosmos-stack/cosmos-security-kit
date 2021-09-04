using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyXXHashExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifyXXHash(this IValueRuleBuilder builder, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyXXHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyXXHash(this IValueRuleBuilder builder, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(xxHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyXXHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return builder.VerifyXXHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyXXHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(xxHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyXXHash<T>(this IValueRuleBuilder<T> builder, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyXXHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyXXHash<T>(this IValueRuleBuilder<T> builder, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(xxHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyXXHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return builder.VerifyXXHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyXXHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(xxHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyXXHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, xxHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyXXHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyXXHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, xxHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(xxHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyXXHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, xxHashTypes type)
        {
            return builder.VerifyXXHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyXXHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, xxHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(xxHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}