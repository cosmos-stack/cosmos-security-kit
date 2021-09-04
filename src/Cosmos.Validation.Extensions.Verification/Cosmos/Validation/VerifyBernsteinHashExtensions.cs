using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyBernsteinHashExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyBernsteinHash(this IValueRuleBuilder builder, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBernsteinHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyBernsteinHash(this IValueRuleBuilder builder, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyBernsteinHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return builder.VerifyBernsteinHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyBernsteinHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyBernsteinHash<T>(this IValueRuleBuilder<T> builder, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBernsteinHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyBernsteinHash<T>(this IValueRuleBuilder<T> builder, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyBernsteinHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return builder.VerifyBernsteinHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyBernsteinHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBernsteinHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return builder.VerifyBernsteinHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyTime33

        public static IPredicateValueRuleBuilder VerifyTime33(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyTime33(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyTime33(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValueRuleBuilder VerifyTime33(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyTime33(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyTime33(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyTime33<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyTime33<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyTime33<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyTime33<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyTime33<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyTime33<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyTime33<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyTime33<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyTime33<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BernsteinHashHandler.Verify<TVal>()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyTime33<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyTime33<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyTime33<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BernsteinHashHandler.CustomVerify<TVal>()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        #endregion
    }
}