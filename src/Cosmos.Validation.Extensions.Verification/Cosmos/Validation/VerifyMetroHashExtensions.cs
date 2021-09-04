using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyMetroHashExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifyMetroHash(this IValueRuleBuilder builder, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMetroHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMetroHash(this IValueRuleBuilder builder, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MetroHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyMetroHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return builder.VerifyMetroHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMetroHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MetroHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMetroHash<T>(this IValueRuleBuilder<T> builder, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMetroHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMetroHash<T>(this IValueRuleBuilder<T> builder, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MetroHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMetroHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return builder.VerifyMetroHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMetroHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MetroHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMetroHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMetroHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMetroHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MetroHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMetroHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return builder.VerifyMetroHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMetroHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MetroHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}